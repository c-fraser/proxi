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

import okhttp3.Headers.Companion.toHeaders
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody

/** [Proxier] is a function which executes proxy requests. */
fun interface Proxier {

  /**
   * Execute the proxy [request].
   *
   * @param request the [Request] to execute
   * @return the [Response]
   * @throws Exception if execution of the proxy request fails
   */
  @Throws(Exception::class) fun execute(request: Request): Response

  companion object {

    /**
     * Create a [Proxier] instance which uses the [httpClient] to execute proxy requests.
     *
     * @param httpClient the [OkHttpClient] to use to execute proxy requests
     * @return the [Proxier]
     */
    @JvmStatic
    @JvmOverloads
    fun create(httpClient: OkHttpClient = OkHttpClient()): Proxier = Proxier { request ->
      okhttp3.Request.Builder()
          .url(request.url)
          .method(request.method, request.body?.takeUnless { it.isEmpty() }?.toRequestBody())
          .headers(request.headers.toHeaders())
          .build()
          .let(httpClient::newCall)
          .execute()
          .use { response ->
            Response(
                request,
                response.code,
                response.headers.toMap(),
                response.body?.use(ResponseBody::bytes))
          }
    }
  }
}
