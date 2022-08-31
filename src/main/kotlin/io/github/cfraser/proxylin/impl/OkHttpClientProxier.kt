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
import java.io.IOException
import java.util.concurrent.CompletableFuture
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Headers.Companion.toHeaders
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody

/**
 * [OkHttpClientProxier] provides [Proxier] implementation that use [OkHttpClient] to execute proxy
 * requests.
 */
object OkHttpClientProxier {

  class Sync @JvmOverloads constructor(private val client: OkHttpClient = OkHttpClient()) :
      Proxier.Sync {

    override fun proxy(request: Request) =
        client.newCall(request.toRequest()).execute().toResponse()
  }

  class Async @JvmOverloads constructor(private val client: OkHttpClient = OkHttpClient()) :
      Proxier.Async {

    override fun proxy(request: Request) =
        client.newCall(request.toRequest()).run {
          CompletableFuture<Response>().apply {
            enqueue(
                object : Callback {
                  override fun onFailure(call: Call, e: IOException) {
                    completeExceptionally(e)
                  }
                  override fun onResponse(call: Call, response: okhttp3.Response) {
                    complete(response.toResponse())
                  }
                })
          }
        }
  }

  /** Convert the [Request] to an [okhttp3.Request]. */
  private fun Request.toRequest(): okhttp3.Request =
      okhttp3.Request.Builder()
          .url(url)
          .method(method, body?.toRequestBody())
          .headers(headers.toHeaders())
          .build()

  /** Convert the [okhttp3.Response] to a [Response]. */
  private fun okhttp3.Response.toResponse(): Response = use {
    Response(it.code, it.headers.toMap(), it.body?.use(ResponseBody::bytes))
  }
}
