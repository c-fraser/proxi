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

import io.javalin.Javalin
import io.javalin.http.Context
import io.javalin.http.Header
import io.javalin.http.HttpStatus
import io.javalin.plugin.Plugin
import io.javalin.security.BasicAuthCredentials
import io.javalin.testtools.HttpClient
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.util.Base64
import java.util.concurrent.CompletableFuture
import kotlin.test.assertEquals
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.ResponseBody
import org.junit.jupiter.api.Test

class ProxylinTest {

  @Test
  fun `proxy a request`() {
    test(proxy = syncProxy()) { it.verifyGet(TARGET_PATH, TARGET_DATA) }
  }

  @Test
  fun `intercept proxy request`() {
    test(target = target(AUTH_TARGET_GET), proxy = syncProxy(onRequest = USE_AUTH)) {
      it.verifyGet(TARGET_PATH, TARGET_DATA)
    }
  }

  @Test
  fun `intercept proxy response`() {
    test(proxy = syncProxy(onResponse = USE_INTERCEPTED_DATA)) {
      it.verifyGet(TARGET_PATH, INTERCEPTED_DATA)
    }
  }

  @Test
  fun `asynchronously proxy a request`() {
    test(proxy = asyncProxy()) { it.verifyGet(TARGET_PATH, TARGET_DATA) }
  }

  @Test
  fun `asynchronously intercept proxy request`() {
    test(target = target(AUTH_TARGET_GET), proxy = asyncProxy(onRequest = USE_AUTH)) {
      it.verifyGet(TARGET_PATH, TARGET_DATA)
    }
  }

  @Test
  fun `asynchronously intercept proxy response`() {
    test(proxy = asyncProxy(onResponse = USE_INTERCEPTED_DATA)) {
      it.verifyGet(TARGET_PATH, INTERCEPTED_DATA)
    }
  }

  @Test
  fun `matched request is not proxied`() {
    proxy(Proxylin.plugin()).run(LOCAL_GET).start(0).use {
      val client = HttpClient(it, OkHttpClient())
      client.verifyGet(LOCAL_PATH, LOCAL_DATA)
    }
  }

  @Test
  fun `unmatched local request is not proxied`() {
    proxy(Proxylin.plugin()).start(0).use {
      val client = HttpClient(it, OkHttpClient())
      assertEquals(HttpStatus.NOT_FOUND.code, client.get("/").use { response -> response.code })
    }
  }

  @Test
  fun `proxy an authorized request`() {
    test(proxy = proxy(Proxylin.plugin(credentials = BasicAuthCredentials(USERNAME, PASSWORD)))) {
        client ->
      assertEquals(
          TARGET_DATA,
          client
              .get(TARGET_PATH) { request ->
                request.header(
                    Header.PROXY_AUTHORIZATION,
                    Credentials.basic(USERNAME, PASSWORD, Charsets.UTF_8))
              }
              .use { response -> response.body?.use(ResponseBody::string) })
    }
  }

  @Test
  fun `unauthorized request is not proxied`() {
    test(proxy = proxy(Proxylin.plugin(credentials = BasicAuthCredentials(USERNAME, PASSWORD)))) {
        client ->
      assertEquals(HttpStatus.UNAUTHORIZED.code, client.get("/").use { response -> response.code })
    }
  }

  private companion object {

    fun test(target: Javalin = target(), proxy: Javalin, testCase: (HttpClient) -> Unit) {
      target.start(0).use { _target ->
        proxy.start(0).use { _proxy ->
          OkHttpClient.Builder()
              .proxySelector(ProxySelector.of(InetSocketAddress(_proxy.port())))
              .build()
              .let { HttpClient(_target, it) }
              .also(testCase)
        }
      }
    }

    const val TARGET_PATH = "/external"
    const val TARGET_DATA = "external"
    const val LOCAL_PATH = "/local"
    const val LOCAL_DATA = "local"
    const val INTERCEPTED_DATA = "intercepted"
    const val USERNAME = "test-user"
    const val PASSWORD = "p@\$sW0rD"

    val TARGET_GET: Javalin.() -> Javalin = { get(TARGET_PATH) { it.result(TARGET_DATA) } }
    val LOCAL_GET: Javalin.() -> Javalin = { get(LOCAL_PATH) { it.result(LOCAL_DATA) } }
    val AUTH_TARGET_GET: Javalin.() -> Javalin = {
      get(TARGET_PATH) {
        it.checkAuth()
        it.result(TARGET_DATA)
      }
    }
    val USE_AUTH: (Request) -> Unit = {
      it.headers =
          it.headers +
              mapOf(
                  Header.AUTHORIZATION to
                      "Basic ${Base64.getEncoder().encodeToString("$USERNAME:$PASSWORD".toByteArray())}")
    }
    val USE_INTERCEPTED_DATA: (Response) -> Unit = { it.body = INTERCEPTED_DATA.toByteArray() }

    fun target(configurer: Javalin.() -> Javalin = TARGET_GET): Javalin =
        Javalin.create { it.showJavalinBanner = false }.run(configurer)

    fun proxy(plugin: Plugin, configurer: Javalin.() -> Javalin = { this }): Javalin =
        Javalin.create {
              it.plugins.register(plugin)
              it.showJavalinBanner = false
            }
            .run(configurer)

    fun syncProxy(onRequest: (Request) -> Unit = {}, onResponse: (Response) -> Unit = {}): Javalin =
        proxy(
            Proxylin.plugin(
                object : Interceptor {
                  override fun intercept(request: Request) = onRequest(request)
                  override fun intercept(response: Response) = onResponse(response)
                }))

    fun asyncProxy(
        onRequest: (Request) -> Unit = {},
        onResponse: (Response) -> Unit = {}
    ): Javalin =
        proxy(
            Proxylin.asyncPlugin(
                object : AsyncInterceptor {
                  override fun intercept(request: Request) =
                      CompletableFuture.supplyAsync<Void> { onRequest(request).let { null } }
                  override fun intercept(response: Response) =
                      CompletableFuture.supplyAsync<Void> { onResponse(response).let { null } }
                }))

    fun HttpClient.verifyGet(path: String, response: String) {
      assertEquals(response, get(path).use { it.body?.string() })
    }

    fun Context.checkAuth(username: String = USERNAME, password: String = PASSWORD) {
      val credentials = checkNotNull(basicAuthCredentials())
      check(credentials.username == username)
      check(credentials.password == password)
    }
  }
}
