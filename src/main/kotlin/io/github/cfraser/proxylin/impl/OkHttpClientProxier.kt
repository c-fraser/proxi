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

import io.github.cfraser.proxylin.Proxier
import io.github.cfraser.proxylin.Request
import io.github.cfraser.proxylin.Response
import okhttp3.Headers.Companion.toHeaders
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody

/**
 * [OkHttpClientProxier] is an [Proxier] implementation that uses [OkHttpClient] to execute proxy
 * requests.
 *
 * @property client the [OkHttpClient] to use to make proxy requests
 */
class OkHttpClientProxier
@JvmOverloads
constructor(private val client: OkHttpClient = OkHttpClient()) : Proxier {

  override fun proxy(request: Request) =
      okhttp3.Request.Builder()
          .url(request.url)
          .method(request.method, request.body?.toRequestBody())
          .headers(request.headers.toHeaders())
          .build()
          .let { client.newCall(it).execute() }
          .use { Response(it.code, it.headers.toMap(), it.body?.use(ResponseBody::bytes)) }

  /*HttpRequest.newBuilder(URI(request.url))
          .method(
              request.method,
              request.body?.let { BodyPublishers.ofByteArray(it) } ?: BodyPublishers.noBody())
          .let {
            request.headers.asSequence().fold(it) { builder, (name, value) ->
              builder.header(name, value)
            }
          }
          .build()
          .let { client.send(it, BodyHandlers.ofByteArray()) }
          .let { Response(it.statusCode(), it.headers().map().toSingleValueMap(), it.body()) }

  private companion object {

    fun <K, V> Map<K, List<V>>.toSingleValueMap() =
        asSequence()
            .mapNotNull { (key, values) -> values.firstOrNull()?.let { value -> key to value } }
            .toMap()
  }*/
}
