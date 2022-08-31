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

/** [Proxier] manages the execution of proxy requests. */
sealed interface Proxier {

  /** [Proxier.Sync] is a synchronous [Proxier]. */
  fun interface Sync : Proxier {

    /**
     * Execute the proxy [request].
     *
     * @param request the [Request] to execute
     * @return the [Response]
     * @throws Exception if execution of the proxy request fails
     */
    @Throws(Exception::class) fun proxy(request: Request): Response
  }

  /** [Proxier.Async] is an asynchronous [Proxier]. */
  fun interface Async : Proxier {

    /**
     * Asynchronously execute the proxy [request].
     *
     * @param request the [Request] to execute
     * @return the [CompletableFuture] of [Response]
     */
    fun proxy(request: Request): CompletableFuture<Response>
  }
}
