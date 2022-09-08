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
import io.javalin.http.servlet.JavalinServlet
import io.javalin.http.servlet.getBasicAuthCredentials
import io.javalin.plugin.Plugin
import io.javalin.security.BasicAuthCredentials
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.CompletableFuture
import kotlin.properties.Delegates.notNull
import org.eclipse.jetty.server.ServerConnector

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
    handler.servlet = app.javalinServlet()
    app.after(handler)
  }

  companion object {

    /**
     * Create an instance of the [Proxylin] plugin.
     *
     * @param interceptors the [Array] of [Interceptor] to use to intercept proxy requests and
     * responses. The first [Interceptor.interceptable] interceptor is used for each proxy request
     * @param proxier the [Proxier] to use to proxy requests
     * @param credentials the [BasicAuthCredentials] required in the [Header.PROXY_AUTHORIZATION]
     * header to proxy the request
     * @return the [Plugin]
     */
    @JvmStatic
    @JvmOverloads
    fun plugin(
        vararg interceptors: Interceptor,
        proxier: Proxier = Proxier.create(),
        credentials: BasicAuthCredentials? = null
    ): Plugin = Proxylin(ProxyHandler.Sync(proxier, credentials, *interceptors))

    /**
     * Create an *asynchronous* instance of the [Proxylin] plugin.
     *
     * @param interceptors the [Array] of [AsyncInterceptor] to use to asynchronously intercept
     * proxy requests and responses. The first [AsyncInterceptor.interceptable] interceptor is used
     * for each proxy request
     * @param proxier the [AsyncProxier] to use to asynchronously proxy requests
     * @param credentials the [BasicAuthCredentials] required in the [Header.PROXY_AUTHORIZATION]
     * header to proxy the request
     * @return the [Plugin]
     */
    @JvmStatic
    @JvmOverloads
    fun asyncPlugin(
        vararg interceptors: AsyncInterceptor,
        proxier: AsyncProxier = AsyncProxier.create(),
        credentials: BasicAuthCredentials? = null
    ): Plugin = Proxylin(ProxyHandler.Async(proxier, credentials, *interceptors))
  }
}

/** [ProxyHandler] is a [Handler] for proxying requests. */
private sealed class ProxyHandler(private val credentials: BasicAuthCredentials?) : Handler {

  var servlet by notNull<JavalinServlet>()

  override fun handle(ctx: Context) {
    when {
      !ctx.isProxyRequest -> return
      !ctx.isAuthorized -> ctx.status(HttpStatus.UNAUTHORIZED)
      else -> ctx.proxy()
    }
  }

  /** Use the [Context] to execute the proxy request and respond with the response. */
  abstract fun Context.proxy()

  /** [ProxyHandler.Sync] is a synchronous [ProxyHandler]. */
  class Sync(
      private val proxier: Proxier,
      credentials: BasicAuthCredentials?,
      private vararg val interceptors: Interceptor
  ) : ProxyHandler(credentials) {

    override fun Context.proxy() {
      val request = toRequest()
      val interceptor = interceptors.firstOrNull { it.interceptable(request) } ?: NO_OP_INTERCEPTOR
      interceptor.intercept(request)
      val response = proxier.execute(request)
      interceptor.intercept(response)
      respond(response)
    }
  }

  /** [ProxyHandler.Async] is an asynchronous [ProxyHandler]. */
  class Async(
      private val proxier: AsyncProxier,
      credentials: BasicAuthCredentials?,
      private vararg val interceptors: AsyncInterceptor
  ) : ProxyHandler(credentials) {

    override fun Context.proxy() {
      future {
        CompletableFuture.supplyAsync { toRequest() }
            .thenApply { request ->
              request to
                  (interceptors.find { it.interceptable(request) } ?: NO_OP_ASYNC_INTERCEPTOR)
            }
            .thenCompose { (request, interceptor) ->
              interceptor.intercept(request).thenApply { request to interceptor }
            }
            .thenCompose { (request, interceptor) ->
              proxier.execute(request).thenApply { response -> response to interceptor }
            }
            .thenCompose { (response, interceptor) ->
              interceptor.intercept(response).thenApply { response }
            }
            .thenAccept { response -> respond(response) }
      }
    }
  }

  /**
   * Determine whether the request should be proxied.
   *
   * > If the [requestPath] is handled via an endpoint or targets the local
   * [io.javalin.config.PrivateConfig.server], then it shouldn't be proxied.
   */
  private val Context.isProxyRequest: Boolean
    get() =
        method().isHttpMethod() &&
            servlet.matcher.findEntries(method(), requestPath).isEmpty() &&
            (InetAddress.getByName(URL(url()).host).hostAddress !in LOCAL_ADDRESSES ||
                servlet.cfg.pvt.server
                    ?.connectors
                    ?.mapNotNull { it as? ServerConnector }
                    ?.none { it.localPort == port() }
                    ?: true)

  /**
   * Check if the request contains the [Header.PROXY_AUTHORIZATION] header matching the
   * [credentials].
   */
  private val Context.isAuthorized: Boolean
    get() =
        credentials == null ||
            credentials == getBasicAuthCredentials(header(Header.PROXY_AUTHORIZATION))

  private companion object {

    val NO_OP_INTERCEPTOR = object : Interceptor {}
    val NO_OP_ASYNC_INTERCEPTOR = object : AsyncInterceptor {}
    val LOCAL_ADDRESSES =
        setOf(
            "localhost",
            InetAddress.getLoopbackAddress().hostAddress,
            InetAddress.getLocalHost().hostAddress)

    /** The [requestPath] is the [Context.path] without the [Context.contextPath] prefix. */
    val Context.requestPath: String
      get() = path().removePrefix(contextPath())

    /** Convert the [Context] to a [Request]. */
    fun Context.toRequest(): Request =
        Request(
            URL(fullUrl()),
            method().name,
            headerMap(),
            bodyAsBytes().takeUnless(ByteArray::isEmpty))

    /** Respond to the request with the [response]. */
    fun Context.respond(response: Response) {
      status(HttpStatus.forStatus(response.statusCode))
      response.headers.forEach { (name, value) -> header(name, value) }
      response.body?.apply { header(Header.CONTENT_LENGTH, "$size") }?.also(this::result)
    }
  }
}
