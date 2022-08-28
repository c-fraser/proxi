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

/** [Proxier] manages the execution of proxy requests. */
fun interface Proxier {

  /**
   * Execute the proxy [request].
   *
   * @param request the [Request] to execute
   * @return the [Response]
   */
  fun proxy(request: Request): Response
}
