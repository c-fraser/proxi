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

// This file was automatically generated by https://github.com/Kotlin/kotlinx-knit. DO NOT EDIT.
package io.github.cfraser.proxylin.knit

import io.github.cfraser.proxylin.Interceptor
import io.github.cfraser.proxylin.Proxylin
import io.github.cfraser.proxylin.Response
import io.javalin.Javalin
import okhttp3.ResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetSocketAddress
import java.net.ProxySelector
import okhttp3.OkHttpClient.Builder as OkHttpClientBuilder
import okhttp3.Request.Builder as RequestBuilder

fun runExample01() { 

  // Initialize a mock web server which is the target for proxy requests.
MockWebServer().use { target ->
  // Enqueue a mock response for the proxied request.
  target.enqueue(MockResponse().setBody("Hello!"))
  // Define a response interceptor to modify the proxy response.
  class ResponseInterceptor : Interceptor {
    override fun intercept(response: Response) {
      // Print the response from the proxy request.
      response.body?.let(::String).also(::println)
      // Change the proxy response body.
      response.body = "Goodbye!".toByteArray()
    }
  }
  // Initialize the `proxylin` plugin.
  val plugin = Proxylin.plugin(ResponseInterceptor())
  // Create and start a `javalin` application with the `proxylin` plugin registered.
  Javalin.create { config -> config.plugins.register(plugin) }
    .start(0)
    .use { proxy ->
      // Initialize an HTTP client that proxies to the `javalin` server.
      val client =
        OkHttpClientBuilder()
          .proxySelector(ProxySelector.of(InetSocketAddress(proxy.port())))
          .build()
      // The HTTP request to the target, which will be proxied by `proxylin`.
      val request = RequestBuilder().url(target.url("/hello")).build()
      // Execute the request then print the response.
      client.newCall(request).execute().use { response ->
        response.body?.use(ResponseBody::string)?.also(::println)
      }
    }
}
}
