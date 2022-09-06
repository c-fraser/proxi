/*
Copyright 2022 c-fraser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package io.github.cfraser.proxylin

import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.http.Header
import io.javalin.http.HttpStatus
import io.javalin.plugin.Plugin
import io.javalin.routing.PathMatcher
import java.util.concurrent.CompletableFuture
import kotlin.properties.Delegates.notNull

/**
 * [Proxylin] is a [Plugin] which enables a [Javalin] server to proxy requests.
 *
 * @property handler the [ProxyHandler] to use to handle request proxying and event interception
 */
class Proxylin private constructor(private val handler: ProxyHandler) : Plugin {

  /**
   * Apply the proxying capabilities to the [app].
   *
   * @param app the [Javalin] that is registering the [Proxylin] plugin
   */
  override fun apply(app: Javalin) {
    handler.matcher = app.javalinServlet().matcher
    app.after(handler)
  }

  companion object {

    /**
     * Create an instance of the [Proxylin] plugin.
     *
     * @param proxier the [Proxier] to use to proxy requests
     * @param onRequest the [Interceptor] function for proxy requests
     * @param onResponse the [Interceptor] function for proxy responses
     * @return the [Plugin]
     */
    @JvmStatic
    @JvmOverloads
    fun create(
        proxier: Proxier = Proxier.create(),
        onRequest: Interceptor<Request> = Interceptor {},
        onResponse: Interceptor<Response> = Interceptor {}
    ): Plugin = Proxylin(ProxyHandler.create(proxier, onRequest, onResponse))

    /**
     * Create an *asynchronous* instance of the [Proxylin] plugin.
     *
     * @param proxier the [AsyncProxier] to use to proxy requests
     * @param onRequest the [AsyncInterceptor] function for proxy requests
     * @param onResponse the [AsyncInterceptor] function for proxy responses
     * @return the [Plugin]
     */
    @JvmStatic
    @JvmOverloads
    fun async(
        proxier: AsyncProxier = AsyncProxier.create(),
        onRequest: AsyncInterceptor<Request> = AsyncInterceptor {
          CompletableFuture.completedFuture(Unit)
        },
        onResponse: AsyncInterceptor<Response> = AsyncInterceptor {
          CompletableFuture.completedFuture(Unit)
        }
    ): Plugin = Proxylin(ProxyHandler.create(proxier, onRequest, onResponse))
  }
}

/** [ProxyHandler] is a [Handler] for proxying requests. */
private sealed class ProxyHandler : Handler {

  var matcher by notNull<PathMatcher>()

  override fun handle(ctx: Context) {
    ctx.takeIf { it.isProxyRequest }?.proxy()
  }

  /** Use the [Context] to execute the proxy request and respond with the response. */
  abstract fun Context.proxy()

  /** [ProxyHandler.Sync] is a synchronous [ProxyHandler]. */
  private class Sync(
      private val proxier: Proxier,
      private val onRequest: Interceptor<Request>,
      private val onResponse: Interceptor<Response>
  ) : ProxyHandler() {

    override fun Context.proxy() {
      val request = toRequest().also(onRequest::intercept)
      val response = proxier.execute(request).also(onResponse::intercept)
      respond(response)
    }
  }

  /** [ProxyHandler.Async] is an asynchronous [ProxyHandler]. */
  private class Async(
      private val proxier: AsyncProxier,
      private val onRequest: AsyncInterceptor<Request>,
      private val onResponse: AsyncInterceptor<Response>
  ) : ProxyHandler() {

    override fun Context.proxy() {
      future {
        CompletableFuture.supplyAsync { toRequest() }
            .thenCompose { request -> onRequest.intercept(request).thenApply { request } }
            .thenCompose { request -> proxier.execute(request) }
            .thenCompose { response -> onResponse.intercept(response).thenApply { response } }
            .thenAccept { response -> respond(response) }
      }
    }
  }

  /**
   * Determine whether the request should be proxied.
   *
   * > If the [requestPath] is handled via an endpoint, then it shouldn't be proxied.
   */
  private val Context.isProxyRequest: Boolean
    get() = method().isHttpMethod() && matcher.findEntries(method(), requestPath).isEmpty()

  companion object {

    /**
     * Create a synchronous [ProxyHandler].
     *
     * @param proxier the [Proxier] to use to proxy requests
     * @param onRequest the [Interceptor] function for proxy requests
     * @param onResponse the [Interceptor] function for proxy responses
     * @return the [ProxyHandler]
     */
    fun create(
        proxier: Proxier,
        onRequest: Interceptor<Request>,
        onResponse: Interceptor<Response>
    ): ProxyHandler = Sync(proxier, onRequest, onResponse)

    /**
     * Create an asynchronous [ProxyHandler].
     *
     * @param proxier the [AsyncProxier] to use to proxy requests
     * @param onRequest the [AsyncInterceptor] function for proxy requests
     * @param onResponse the [AsyncInterceptor] function for proxy responses
     * @return the [ProxyHandler]
     */
    fun create(
        proxier: AsyncProxier = AsyncProxier.create(),
        onRequest: AsyncInterceptor<Request>,
        onResponse: AsyncInterceptor<Response>
    ): ProxyHandler = Async(proxier, onRequest, onResponse)

    /** The [requestPath] is the [Context.path] without the [Context.contextPath] prefix. */
    private val Context.requestPath: String
      get() = path().removePrefix(contextPath())

    /** Convert the [Context] to a [Request]. */
    private fun Context.toRequest(): Request =
        Request(fullUrl(), method().name, headerMap(), bodyAsBytes().takeUnless(ByteArray::isEmpty))

    /** Respond to the request with the [response]. */
    private fun Context.respond(response: Response) {
      status(HttpStatus.forStatus(response.statusCode))
      response.headers.forEach { (name, value) -> header(name, value) }
      response.body?.apply { header(Header.CONTENT_LENGTH, "$size") }?.also(this::result)
    }
  }
}
