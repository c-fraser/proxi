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
 * [Interceptor] intercepts a proxy request and the corresponding response. The interception of
 * mutable [Request] and [Response] enables the dynamic transformation of proxied data.
 */
@JvmDefaultWithCompatibility
interface Interceptor {

  /**
   * Determine whether the [request] should be intercepted.
   *
   * @param request the proxy request capable of being intercepted
   * @return `true` if the request and response should be intercepted, otherwise `false`
   */
  fun interceptable(request: Request): Boolean = true

  /**
   * Intercept the [request] before it is executed.
   *
   * @param request the intercepted [Request]
   * @throws Exception if request interception fails
   */
  @Throws(Exception::class) fun intercept(request: Request) {}

  /**
   * Intercept the [response] after it is received.
   *
   * @param response the intercepted [Response]
   * @throws Exception if response interception fails
   */
  @Throws(Exception::class) fun intercept(response: Response) {}
}

/** [AsyncInterceptor] is an asynchronous [Interceptor]. */
@JvmDefaultWithCompatibility
interface AsyncInterceptor {

  /**
   * Synchronously determine whether the [request] should be intercepted.
   *
   * @param request the proxy request capable of being intercepted
   * @return `true` if the request and response should be intercepted, otherwise `false`
   */
  fun interceptable(request: Request): Boolean = true

  /**
   * Asynchronously intercept the [request] before it is executed.
   *
   * @param request the intercepted [Request]
   * @return the [CompletableFuture] of [Unit]
   */
  fun intercept(request: Request): CompletableFuture<Void> = CompletableFuture.completedFuture(null)

  /**
   * Asynchronously intercept the [response] after it is received.
   *
   * @param response the intercepted [Response]
   * @return the [CompletableFuture] of [Unit]
   */
  fun intercept(response: Response): CompletableFuture<Void> =
      CompletableFuture.completedFuture(null)
}
