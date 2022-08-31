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

import java.util.concurrent.CompletableFuture

/**
 * [Proxier] manages the execution of proxy requests. Proxy requests and responses are intercepted
 * by the [interceptor].
 */
sealed interface Proxier {

  /** The [Interceptor] to use to intercept proxy requests and responses. */
  val interceptor: Interceptor

  /** [Proxier.Sync] is a synchronous [Proxier]. */
  @JvmDefaultWithCompatibility
  interface Sync : Proxier {

    /** The synchronous [interceptor] to use to intercept proxy requests and responses. */
    override val interceptor: Interceptor.Sync

    /**
     * Execute the proxy [request].
     *
     * @param request the [Request] to execute
     * @return the [Response]
     * @throws Exception if execution of the proxy request fails
     */
    @Throws(Exception::class) fun execute(request: Request): Response

    /**
     * Proxy the [request].
     *
     * The [request] and [Response] are intercepted by the [interceptor].
     *
     * @param request the [Request] to proxy
     * @return the [Response]
     * @throws Exception if proxying the request fails
     */
    @Throws(Exception::class)
    fun proxy(request: Request): Response =
        execute(request.also(interceptor::intercept)).also(interceptor::intercept)
  }

  /** [Proxier.Async] is an asynchronous [Proxier]. */
  @JvmDefaultWithCompatibility
  interface Async : Proxier {

    /** The asynchronous [interceptor] to use to intercept proxy requests and responses. */
    override val interceptor: Interceptor.Async

    /**
     * Asynchronously execute the proxy [request].
     *
     * @param request the [Request] to execute
     * @return the [CompletableFuture] of [Response]
     */
    fun execute(request: Request): CompletableFuture<Response>

    /**
     * Proxy the [request].
     *
     * The [request] and [Response] are intercepted by the [interceptor].
     *
     * @param request the [Request] to proxy
     * @return the [Response]
     */
    fun proxy(request: Request): CompletableFuture<Response> =
        interceptor
            .intercept(request)
            .thenApply { request }
            .thenCompose { execute(it) }
            .thenCompose { response -> interceptor.intercept(response).thenApply { response } }
  }
}
