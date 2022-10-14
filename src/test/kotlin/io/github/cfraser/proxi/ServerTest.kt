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

import io.github.cfraser.proxi.ServerTest.ErrorInterceptor.Intercept
import io.javalin.Javalin
import io.ktor.network.tls.certificates.generateCertificate
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.nio.file.Path
import java.nio.file.Paths
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.io.path.inputStream
import kotlin.test.assertEquals
import kotlin.test.fail
import okhttp3.Credentials as OkCredentials
import okhttp3.OkHttpClient
import okhttp3.Request as OkRequest
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response as OkResponse
import okhttp3.ResponseBody
import org.eclipse.jetty.server.Server as JettyServer
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.junit.jupiter.api.Test

/*
The HTTPS tests require the (proxy) server certificate and key to be present (in the `resources`
directory). The artifacts can be generated via the following `openssl` commands.

openssl genrsa -out cert.key 2048 && openssl req -new -x509 -key cert.key -out cert.pem
*/
class ServerTest {

  @Test
  fun `proxy an HTTP request`() {
    verifyServer()
  }

  @Test
  fun `proxy an authorized HTTP request`() {
    verifyServer(credentials = Credentials(USERNAME, PASSWORD))
  }

  @Test
  fun `unauthorized HTTP request is not proxied`() {
    verifyServer(credentials = Credentials(USERNAME, PASSWORD), error = ProxyError.UNAUTHORIZED)
  }

  @Test
  fun `intercept an HTTP request`() {
    verifyServer(RequestInterceptor)
  }

  @Test
  fun `intercept an HTTP response`() {
    verifyServer(ResponseInterceptor)
  }

  @Test
  fun `first interceptor intercepts an HTTP request`() {
    verifyServer(RequestInterceptor, FailInterceptor)
  }

  @Test
  fun `failed to execute HTTP proxy request`() {
    verifyServer(error = ProxyError.REQUEST_FAILURE)
  }

  @Test
  fun `failed to intercept HTTP proxy request`() {
    verifyServer(ErrorInterceptor(Intercept.REQUEST), error = ProxyError.INTERCEPT_FAILURE)
  }

  @Test
  fun `failed to intercept HTTP proxy response`() {
    verifyServer(ErrorInterceptor(Intercept.RESPONSE), error = ProxyError.INTERCEPT_FAILURE)
  }

  @Test
  fun `proxy an HTTPS request`() {
    verifyServer(secure = true)
  }

  @Test
  fun `proxy an authorized HTTPS request`() {
    verifyServer(secure = true, credentials = Credentials(USERNAME, PASSWORD))
  }

  @Test
  fun `unauthorized HTTPS request is not proxied`() {
    verifyServer(
        secure = true,
        credentials = Credentials(USERNAME, PASSWORD),
        error = ProxyError.UNAUTHORIZED)
  }

  @Test
  fun `intercept an HTTPS request`() {
    verifyServer(RequestInterceptor, secure = true)
  }

  @Test
  fun `intercept an HTTPS response`() {
    verifyServer(ResponseInterceptor, secure = true)
  }

  @Test
  fun `first interceptor intercepts an HTTPS request`() {
    verifyServer(RequestInterceptor, FailInterceptor, secure = true)
  }

  @Test
  fun `failed to execute HTTPS proxy request`() {
    verifyServer(secure = true, error = ProxyError.REQUEST_FAILURE)
  }

  @Test
  fun `failed to intercept HTTPS proxy request`() {
    verifyServer(
        ErrorInterceptor(Intercept.REQUEST), secure = true, error = ProxyError.INTERCEPT_FAILURE)
  }

  @Test
  fun `failed to intercept HTTPS proxy response`() {
    verifyServer(
        ErrorInterceptor(Intercept.RESPONSE), secure = true, error = ProxyError.INTERCEPT_FAILURE)
  }

  @Test
  fun `failed to decode proxy request (URI too long)`() {
    verifyServer(error = ProxyError.URI_TOO_LONG)
  }

  @Test
  fun `failed to decode proxy request (header fields too large)`() {
    verifyServer(error = ProxyError.HEADER_FIELDS_TOO_LARGE)
  }

  private object RequestInterceptor : Interceptor {

    override fun interceptable(request: Request) = request.method == "POST"

    override fun intercept(request: Request) {
      request.body = INTERCEPTED_DATA.toByteArray()
    }
  }

  private object ResponseInterceptor : Interceptor {

    override fun interceptable(request: Request) = request.method == "POST"

    override fun intercept(response: Response) {
      response.body = INTERCEPTED_DATA.toByteArray()
    }
  }

  private object FailInterceptor : Interceptor {

    override fun interceptable(request: Request) = request.method == "POST"

    override fun intercept(request: Request) =
        fail("${FailInterceptor::class.simpleName} intercepted request")

    override fun intercept(response: Response) =
        fail("${FailInterceptor::class.simpleName} intercepted response")
  }

  private class ErrorInterceptor(private val intercept: Intercept) : Interceptor {

    enum class Intercept {
      REQUEST,
      RESPONSE
    }

    override fun intercept(request: Request) {
      if (intercept == Intercept.REQUEST)
          error("${ErrorInterceptor::class.simpleName} intercepted request")
    }

    override fun intercept(response: Response) {
      if (intercept == Intercept.RESPONSE)
          error("${ErrorInterceptor::class.simpleName} intercepted response")
    }
  }

  private enum class ProxyError(val responseStatus: HttpResponseStatus) {
    UNAUTHORIZED(HttpResponseStatus.UNAUTHORIZED),
    REQUEST_FAILURE(HttpResponseStatus.BAD_GATEWAY),
    INTERCEPT_FAILURE(HttpResponseStatus.INTERNAL_SERVER_ERROR),
    URI_TOO_LONG(HttpResponseStatus.REQUEST_URI_TOO_LONG),
    HEADER_FIELDS_TOO_LARGE(HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)
  }

  internal companion object {

    private const val PORT = 8787
    private const val TARGET_PATH = "/external"
    private const val TARGET_DATA = "external"
    private const val INTERCEPTED_DATA = "intercepted"
    private const val USERNAME = "test-user"
    private const val PASSWORD = "p@\$sW0rD"

    val PROXY_CERTIFICATE =
        checkNotNull(getResource("cert.pem")) { "Failed to get proxy certificate" }
    val PROXY_PRIVATE_KEY =
        checkNotNull(getResource("cert.key")) { "Failed to get proxy private key" }
    private val CLIENT_TRUSTSTORE = newTruststore(PROXY_CERTIFICATE)
    val PROXY_CLIENT_TRUST_MANGER = newX509TrustManager(CLIENT_TRUSTSTORE)
    val PROXY_CLIENT_SOCKET_FACTORY: SSLSocketFactory =
        newSSLContext(PROXY_CLIENT_TRUST_MANGER).socketFactory

    private fun verifyServer(
        vararg interceptors: Interceptor,
        secure: Boolean = false,
        credentials: Credentials? = null,
        error: ProxyError? = null
    ) {
      webServer(secure = secure) { baseUrl ->
        val proxier =
            error
                ?.takeIf { it == ProxyError.REQUEST_FAILURE }
                ?.let { Proxier { error("Failed to proxy request") } }
        val (server, client) =
            if (secure)
                Server.create(
                    *interceptors,
                    proxier = proxier
                            ?: Proxier.create(
                                newClient(
                                    proxy = null, sslSocketFactory = insecureSSLSocketFactory())),
                    certificatePath = PROXY_CERTIFICATE,
                    privateKeyPath = PROXY_PRIVATE_KEY,
                    credentials = credentials) to
                    newClient(
                        sslSocketFactory = PROXY_CLIENT_SOCKET_FACTORY to PROXY_CLIENT_TRUST_MANGER)
            else
                Server.create(*interceptors, proxier = proxier, credentials = credentials) to
                    newClient()
        server.start(PORT).use {
          client.proxyRequests(baseUrl, interceptors, credentials, error?.responseStatus)
        }
      }
    }

    private fun newSSLContext(vararg trustManagers: TrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, trustManagers, null) }

    private fun newTruststore(trustedCertificate: Path): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
          load(null, null)
          val factory = CertificateFactory.getInstance("X.509")
          val certificate =
              trustedCertificate.inputStream().buffered().use(factory::generateCertificate)
          setCertificateEntry(Server::class.simpleName?.lowercase(), certificate)
        }

    private fun newX509TrustManager(
        @Suppress("SameParameterValue") truststore: KeyStore
    ): X509TrustManager =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(truststore) }
            .trustManagers
            .firstOrNull() as? X509TrustManager
            ?: error("Failed to initialize X509 trust manager")

    private fun insecureSSLSocketFactory(): Pair<SSLSocketFactory, X509TrustManager> =
        newSSLContext(*InsecureTrustManagerFactory.INSTANCE.trustManagers).socketFactory to
            (InsecureTrustManagerFactory.INSTANCE.trustManagers.find { it is X509TrustManager }
                as? X509TrustManager
                ?: fail("Failed to initialize X.509 trust manager"))

    private fun getResource(name: String): Path? =
        ServerTest::class.java.classLoader.getResource(name)?.toURI()?.let(Paths::get)

    private fun newClient(
        proxy: Int? = PORT,
        sslSocketFactory: Pair<SSLSocketFactory, X509TrustManager>? = null
    ): OkHttpClient =
        OkHttpClient.Builder()
            .run { proxy?.let { proxySelector(ProxySelector.of(InetSocketAddress(it))) } ?: this }
            .run {
              sslSocketFactory?.let { (socketFactory, trustManager) ->
                sslSocketFactory(socketFactory, trustManager)
              }
                  ?: this
            }
            .build()

    private fun webServer(secure: Boolean = false, block: (String) -> Unit) {
      Javalin.create {
            if (secure)
                it.jetty.server {
                  JettyServer().apply {
                    val sslContextFactory =
                        SslContextFactory.Server().apply {
                          keyStore =
                              generateCertificate(
                                  keyAlias = USERNAME,
                                  keyPassword = PASSWORD,
                                  jksPassword = PASSWORD)
                          keyStorePassword = PASSWORD
                          isTrustAll = true
                        }
                    val sslConnector = ServerConnector(server, sslContextFactory)
                    connectors = arrayOf(sslConnector)
                  }
                }
            it.showJavalinBanner = false
          }
          .get(TARGET_PATH) { it.result(TARGET_DATA) }
          .post(TARGET_PATH) { it.result(it.body()) }
          .start(0)
          .use { block("http${"s".takeIf { secure }.orEmpty()}://localhost:${it.port()}") }
    }

    private fun OkHttpClient.get(url: String, credentials: Credentials?): String =
        OkRequest.Builder()
            .url(url)
            .credentials(credentials)
            .build()
            .let(::newCall)
            .execute()
            .data()

    private fun OkHttpClient.post(url: String, data: String, credentials: Credentials?): String =
        OkRequest.Builder()
            .url(url)
            .method("POST", data.toRequestBody())
            .credentials(credentials)
            .build()
            .let(::newCall)
            .execute()
            .data()

    private fun OkRequest.Builder.credentials(credentials: Credentials?): OkRequest.Builder =
        credentials?.let { (username, password) ->
          header("Proxy-Authorization", OkCredentials.basic(username, password))
        }
            ?: this

    private fun OkResponse.data(): String =
        use { it.body?.use(ResponseBody::string) } ?: fail("No response data in $this")

    private fun OkHttpClient.proxyRequests(
        baseUrl: String,
        interceptors: Array<out Interceptor>,
        credentials: Credentials?,
        responseStatus: HttpResponseStatus? = null
    ) {
      if (responseStatus == null) {
        assertEquals(TARGET_DATA, get("$baseUrl$TARGET_PATH", credentials))
        assertEquals(
            if (interceptors.isEmpty()) TARGET_DATA else INTERCEPTED_DATA,
            post("$baseUrl$TARGET_PATH", TARGET_DATA, credentials))
      } else
          assertEquals(
              responseStatus.code(),
              OkRequest.Builder()
                  .url(
                      "$baseUrl${
                        if (responseStatus == HttpResponseStatus.REQUEST_URI_TOO_LONG)
                          "/${newRandomString(Server.MAX_URI_SIZE + 1)}"
                        else TARGET_PATH}")
                  .run {
                    if (responseStatus == HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)
                        header(
                            "${HttpHeaderNames.PROXY_AUTHORIZATION}",
                            "Basic ${newRandomString(Server.MAX_HEADER_SIZE + 1)}")
                    else this
                  }
                  .build()
                  .let(::newCall)
                  .execute()
                  .code)
    }

    private fun newRandomString(size: Int): String =
        with('a'..'z') { (1..size).map { random() } }.joinToString("")
  }
}
