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

/**
 * [Response] is the HTTP response for a proxy request.
 *
 * @property statusCode the proxy response status code
 * @property headers the proxy response headers
 * @property body the proxy response body
 */
class Response
internal constructor(
    @JvmField var statusCode: Int,
    @JvmField var headers: Map<String, String>,
    @JvmField var body: ByteArray?
)
