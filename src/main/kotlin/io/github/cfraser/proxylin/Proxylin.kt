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

import io.github.cfraser.proxylin.impl.NoOpInterceptor
import io.github.cfraser.proxylin.impl.OkHttpClientProxier
import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.http.Handler
import io.javalin.http.HttpStatus
import io.javalin.plugin.Plugin
import io.javalin.routing.PathMatcher

/**
 * [Proxylin] is a [Plugin] which enables a [Javalin] server to proxy requests.
 *
 * @property proxier the [Proxier] used to make proxy requests
 * @property interceptor the [Interceptor] used to intercept proxy requests and responses
 */
class Proxylin
@JvmOverloads
constructor(
    private val proxier: Proxier = OkHttpClientProxier(),
    private val interceptor: Interceptor = NoOpInterceptor
) : Plugin {

  /** Apply the proxying capabilities to the [app]. */
  override fun apply(app: Javalin) {
    app.after(ProxyHandler(app.javalinServlet().matcher))
  }

  /**
   * [ProxyHandler] is a [Handler] for proxying requests.
   *
   * @property matcher the [PathMatcher] to use to determine if the request should be proxied
   */
  inner class ProxyHandler(private val matcher: PathMatcher) : Handler {

    override fun handle(ctx: Context) {
      if (!ctx.isProxyRequest) return
      val request =
          Request(ctx.fullUrl(), ctx.method().name, ctx.headerMap(), ctx.bodyAsBytes())
              .also(interceptor::intercept)
      val response = proxier.proxy(request).also(interceptor::intercept)
      ctx.status(HttpStatus.forStatus(response.statusCode))
      response.headers.forEach { (name, value) -> ctx.header(name, value) }
      response.body?.also(ctx::result)
    }

    /**
     * Determine whether the request ([Context]) should be proxied.
     *
     * > If the request URI (path) is handled by an endpoint, then it shouldn't be proxied.
     */
    private val Context.isProxyRequest: Boolean
      get() =
          method().isHttpMethod() &&
              matcher.findEntries(method(), path().removePrefix(contextPath())).isEmpty()
  }
}
