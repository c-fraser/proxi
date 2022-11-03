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
package io.github.cfraser.proxi

/**
 * [Interceptor] intercepts a proxy request and the corresponding response. The interception of
 * mutable [Request] and [Response] enables the dynamic transformation of proxied data.
 *
 * An [Interceptor] instance may intercept requests and responses concurrently. If the [Interceptor]
 * implementation is not stateless, then synchronization is required.
 */
@JvmDefaultWithCompatibility
interface Interceptor {

  /**
   * The [Proxier] to use to execute [Request]s intercepted by this [Interceptor].
   *
   * If [proxier] is `null` then the *global* [Proxier] will be used.
   *
   * @see Server.create to specify a *global* [Proxier]
   */
  val proxier: Proxier?
    get() = null

  /**
   * Determine whether the [request] should be intercepted by `this` [Interceptor].
   *
   * @param request the proxy [Request] capable of being intercepted
   * @return `true` if the request and response should be intercepted, otherwise `false`
   * @throws Exception if the interceptable check fails
   */
  @Throws(Exception::class) fun interceptable(request: Request): Boolean = false

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
