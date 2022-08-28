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
package io.github.cfraser.proxylin.impl

import io.github.cfraser.proxylin.Interceptor
import io.github.cfraser.proxylin.Request
import io.github.cfraser.proxylin.Response

/**
 * [NoOpInterceptor] is an [Interceptor] implementation that performs no operations on the
 * intercepted requests and responses.
 */
object NoOpInterceptor : Interceptor {

  override fun intercept(request: Request) = Unit
  override fun intercept(response: Response) = Unit
}
