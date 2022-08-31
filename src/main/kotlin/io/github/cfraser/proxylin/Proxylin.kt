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

import io.github.cfraser.proxylin.impl.OkHttpClientProxier
import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.http.Header
import io.javalin.http.HttpStatus
import io.javalin.plugin.Plugin
import io.javalin.routing.PathMatcher

/**
 * [Proxylin] is a [Plugin] which enables a [Javalin] server to proxy requests.
 *
 * @property proxier the [Proxier] used to proxy requests
 */
class Proxylin
@JvmOverloads
constructor(private val proxier: Proxier = OkHttpClientProxier.Sync()) : Plugin {

  /** Apply the proxying capabilities to the [app]. */
  override fun apply(app: Javalin) {
    val matcher = app.javalinServlet().matcher
    val handler =
        when (proxier) {
          is Proxier.Sync -> ProxyHandler.Sync(proxier, matcher)
          is Proxier.Async -> ProxyHandler.Async(proxier, matcher)
        }
    app.after(handler)
  }

  /** [ProxyHandler] is a [Handler] for proxying requests. */
  private sealed class ProxyHandler(private val matcher: PathMatcher) : Handler {

    override fun handle(ctx: Context) {
      ctx.takeIf { it.isProxyRequest }?.proxy()
    }

    /** Use the [Context] to execute the proxy request and respond with the response. */
    abstract fun Context.proxy()

    /**
     * Determine whether the request should be proxied.
     *
     * > If the [requestPath] is handled via an endpoint, then it shouldn't be proxied.
     */
    private val Context.isProxyRequest: Boolean
      get() = method().isHttpMethod() && matcher.findEntries(method(), requestPath).isEmpty()

    /** [ProxyHandler.Sync] is a synchronous [ProxyHandler]. */
    class Sync(private val proxier: Proxier.Sync, matcher: PathMatcher) : ProxyHandler(matcher) {

      override fun Context.proxy() {
        val request = toRequest()
        val response = proxier.proxy(request)
        respond(response)
      }
    }

    /** [ProxyHandler.Async] is an asynchronous [ProxyHandler]. */
    class Async(private val proxier: Proxier.Async, matcher: PathMatcher) : ProxyHandler(matcher) {

      override fun Context.proxy() {
        val request = toRequest()
        val response = proxier.proxy(request)
        future(response) { respond(it) }
      }
    }

    private companion object {

      /** The [requestPath] is the [Context.path] without the [Context.contextPath] prefix. */
      val Context.requestPath: String
        get() = path().removePrefix(contextPath())

      /** Convert the [Context] to a [Request]. */
      fun Context.toRequest(): Request =
          Request(
              fullUrl(), method().name, headerMap(), bodyAsBytes().takeUnless(ByteArray::isEmpty))

      /** Respond to the request with the [response]. */
      fun Context.respond(response: Response) {
        status(HttpStatus.forStatus(response.statusCode))
        response.headers.forEach { (name, value) -> header(name, value) }
        response.body?.apply { header(Header.CONTENT_LENGTH, "$size") }?.also(this::result)
      }
    }
  }
}
