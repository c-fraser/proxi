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

import java.io.IOException
import java.util.concurrent.CompletableFuture
import okhttp3.Call
import okhttp3.Callback
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
     * Create an instance of [Proxier] which uses the [client] to make proxy requests.
     *
     * @param client the [OkHttpClient] to use to make HTTP requests
     * @return the [Proxier]
     */
    @JvmStatic
    @JvmOverloads
    fun create(client: OkHttpClient = OkHttpClient()): Proxier = ProxierImpl(client)
  }
}

/** [AsyncProxier] is an asynchronous [Proxier]. */
fun interface AsyncProxier {

  /**
   * Asynchronously execute the proxy [request].
   *
   * @param request the [Request] to execute
   * @return the [CompletableFuture] of [Response]
   */
  fun execute(request: Request): CompletableFuture<Response>

  companion object {

    /**
     * Create an instance of [AsyncProxier] which uses the [client] to make proxy requests
     * asynchronously.
     *
     * @param client the [OkHttpClient] to use to make HTTP requests
     * @return the [AsyncProxier]
     */
    @JvmStatic
    @JvmOverloads
    fun create(client: OkHttpClient = OkHttpClient()): AsyncProxier = AsyncProxierImpl(client)
  }
}

/**
 * [ProxierImpl] is a [Proxier] implementation that use [OkHttpClient] to execute proxy requests.
 */
private class ProxierImpl(private val client: OkHttpClient = OkHttpClient()) : Proxier {

  override fun execute(request: Request) =
      client.newCall(request.toRequest()).execute().toResponse()
}

/**
 * [AsyncProxierImpl] is a [AsyncProxier] implementation that use [OkHttpClient] to execute proxy
 * requests asynchronously.
 */
private class AsyncProxierImpl(private val client: OkHttpClient = OkHttpClient()) : AsyncProxier {

  override fun execute(request: Request) =
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
