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
 * [Interceptor] is a function which intercepts [T] events.
 *
 * In the context of [Proxylin], [Interceptor] is used to intercept *mutable* [Request] and
 * [Response], enabling the dynamic transformation of proxy requests and responses.
 */
fun interface Interceptor<in T> {

  /**
   * Intercept the proxy [event].
   *
   * @param event the intercepted [event]
   * @throws Exception if request interception fails
   */
  @Throws(Exception::class) fun intercept(event: T)
}

/** [AsyncInterceptor] is an asynchronous [Interceptor]. */
fun interface AsyncInterceptor<in T> {

  /**
   * Asynchronously intercept the [event].
   *
   * @param event the intercepted [event]
   * @return the [CompletableFuture] of [Unit] representing the state of the interception
   */
  fun intercept(event: T): CompletableFuture<Unit?>
}
