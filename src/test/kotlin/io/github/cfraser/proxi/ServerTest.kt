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

import com.google.common.jimfs.Configuration
import com.google.common.jimfs.Jimfs
import io.github.cfraser.proxi.ServerTest.ErrorInterceptor.Intercept
import io.javalin.Javalin
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.net.URI
import java.nio.file.Path
import java.nio.file.Paths
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.io.path.createDirectory
import kotlin.io.path.inputStream
import kotlin.io.path.writeText
import kotlin.test.assertEquals
import kotlin.test.fail
import okhttp3.OkHttpClient
import okhttp3.Request as OkRequest
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response as OkResponse
import okhttp3.ResponseBody
import okhttp3.tls.HeldCertificate
import org.eclipse.jetty.server.Server as JettyServer
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.zeroturnaround.exec.ProcessExecutor

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
    verifyServer(error = ProxyError.PROXIER_ERROR)
  }

  @Test
  fun `failed to intercept HTTP proxy request`() {
    verifyServer(ErrorInterceptor(Intercept.REQUEST), error = ProxyError.INTERCEPT_ERROR)
  }

  @Test
  fun `failed to intercept HTTP proxy response`() {
    verifyServer(ErrorInterceptor(Intercept.RESPONSE), error = ProxyError.INTERCEPT_ERROR)
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
    verifyServer(secure = true, error = ProxyError.PROXIER_ERROR)
  }

  @Test
  fun `failed to intercept HTTPS proxy request`() {
    verifyServer(
        ErrorInterceptor(Intercept.REQUEST), secure = true, error = ProxyError.INTERCEPT_ERROR)
  }

  @Test
  fun `failed to intercept HTTPS proxy response`() {
    verifyServer(
        ErrorInterceptor(Intercept.RESPONSE), secure = true, error = ProxyError.INTERCEPT_ERROR)
  }

  @Test
  fun `failed to decode proxy request (URI too long)`() {
    verifyServer(error = ProxyError.URI_TOO_LONG)
  }

  @Test
  fun `failed to decode proxy request (header fields too large)`() {
    verifyServer(error = ProxyError.HEADER_FIELDS_TOO_LARGE)
  }

  @Test
  fun `unable to proxy HTTPS request`() {
    val exception =
        assertThrows<IOException> {
          verifyServer(secure = true, error = ProxyError.HTTPS_UNSUPPORTED)
        }
    assertEquals("Unexpected response code for CONNECT: 501", exception.message)
  }

  @Test
  fun `unable to proxy HTTPS request without hostname`() {
    val exception =
        assertThrows<IOException> { verifyServer(secure = true, error = ProxyError.INVALID_HOST) }
    assertEquals("Unexpected response code for CONNECT: 400", exception.message)
  }

  @Test
  fun `verify receiving HTTP request (invalid proxy request URL)`() {
    webServer {
      Server.create().start(PORT).use {
        assertEquals(
            ProxyError.PROXIER_ERROR.responseStatus?.code(),
            OkHttpClient()
                .newCall(OkRequest.Builder().url("http://localhost:$PORT").build())
                .execute()
                .code)
      }
    }
  }

  @Test
  fun `verify proxying HTTP request by specifying destination in interceptor`() {
    webServer { baseUrl ->
      Server.create(
              object : Interceptor {
                override fun interceptable(request: Request) = true
                override fun intercept(request: Request) {
                  request.uri = URI("$baseUrl$TARGET_PATH")
                }
              })
          .start(PORT)
          .use {
            val response =
                OkHttpClient()
                    .newCall(OkRequest.Builder().url("http://localhost:$PORT").build())
                    .execute()
            assertEquals(200, response.code)
            assertEquals(TARGET_DATA, response.data())
          }
    }
  }

  /**
   * [hey](https://github.com/rakyll/hey) and [mkcert](https://github.com/FiloSottile/mkcert)
   * (`mkcert -install`) must be installed to (successfully) run the [PerformanceTest] tests.
   */
  @Tag("performance")
  class PerformanceTest {

    @Test
    fun `measure HTTP proxy server performance`() {
      Server.create().start(PORT).use {
        val command =
            listOf(
                "hey",
                "-n",
                "10000",
                "-m",
                "GET",
                "-x",
                "http://localhost:$PORT",
                @Suppress("HttpUrlsUsage") "http://httpbin.org/get")
        exec(command, readOutput = false)
        exec(command)?.also(::println)
      }
    }

    @Test
    fun `measure HTTPS proxy server performance`() {
      val rootCAPath =
          exec(listOf("mkcert", "-CAROOT"))?.trim()?.let(Paths::get)
              ?: fail("Failed to GET (mkcert) root CA path")
      val certificatePath = rootCAPath.resolve("rootCA.pem")
      val privateKeyPath = rootCAPath.resolve("rootCA-key.pem")
      Server.create(certificatePath = certificatePath, privateKeyPath = privateKeyPath)
          .start(PORT)
          .use {
            val command =
                listOf(
                    "hey",
                    "-n",
                    "10000",
                    "-m",
                    "GET",
                    "-x",
                    "http://localhost:$PORT",
                    "https://httpbin.org/get")
            exec(command, readOutput = false)
            exec(command)?.also(::println)
          }
    }
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

    override fun interceptable(request: Request) = true

    override fun intercept(request: Request) {
      if (intercept == Intercept.REQUEST)
          error("${ErrorInterceptor::class.simpleName} intercepted request")
    }

    override fun intercept(response: Response) {
      if (intercept == Intercept.RESPONSE)
          error("${ErrorInterceptor::class.simpleName} intercepted response")
    }
  }

  private enum class ProxyError(val responseStatus: HttpResponseStatus?) {
    UNAUTHORIZED(HttpResponseStatus.PROXY_AUTHENTICATION_REQUIRED),
    PROXIER_ERROR(HttpResponseStatus.BAD_GATEWAY),
    INTERCEPT_ERROR(HttpResponseStatus.INTERNAL_SERVER_ERROR),
    URI_TOO_LONG(HttpResponseStatus.REQUEST_URI_TOO_LONG),
    HEADER_FIELDS_TOO_LARGE(HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE),
    HTTPS_UNSUPPORTED(null),
    INVALID_HOST(null)
  }

  internal companion object {

    const val PORT = 8787
    private const val TARGET_PATH = "/external"
    private const val TARGET_DATA = "external"
    private const val INTERCEPTED_DATA = "intercepted"
    private const val USERNAME = "test-user"
    private const val PASSWORD = "p@\$sW0rD"

    private val FILE_SYSTEM = Jimfs.newFileSystem(Configuration.unix())
    fun String.asFile(file: String): Path =
        FILE_SYSTEM.getPath("/${UUID.randomUUID()}")
            .createDirectory()
            .run { resolve(file) }
            .also { it.writeText(this) }

    val LOCALHOST: String = InetAddress.getByName("localhost").canonicalHostName
    private val LOCALHOST_CERTIFICATE
      get() = HeldCertificate.Builder().addSubjectAlternativeName(LOCALHOST).build()
    private val PROXY_CERTIFICATE = HeldCertificate.Builder().certificateAuthority(0).build()
    val PROXY_CERTIFICATE_PATH = PROXY_CERTIFICATE.certificatePem().asFile("proxy.pem")
    val PROXY_PRIVATE_KEY_PATH = PROXY_CERTIFICATE.privateKeyPkcs8Pem().asFile("proxy.key")
    private val CLIENT_TRUSTSTORE = newTruststore(PROXY_CERTIFICATE_PATH)
    val PROXY_CLIENT_TRUST_MANGER = newX509TrustManager(CLIENT_TRUSTSTORE)
    val PROXY_CLIENT_SOCKET_FACTORY: SSLSocketFactory =
        newSSLContext(PROXY_CLIENT_TRUST_MANGER).socketFactory

    private fun verifyServer(
        vararg interceptors: Interceptor,
        secure: Boolean = false,
        credentials: Credentials? = null,
        error: ProxyError? = null
    ) {
      webServer(
          secure = secure,
          host = if (error == ProxyError.INVALID_HOST) "127.0.0.1" else "localhost") { baseUrl ->
            val proxier =
                error
                    ?.takeIf { it == ProxyError.PROXIER_ERROR }
                    ?.let { Proxier { error("Failed to proxy request") } }
            val (server, client) =
                if (secure && error != ProxyError.HTTPS_UNSUPPORTED)
                    Server.create(
                        *interceptors,
                        proxier = proxier
                                ?: Proxier.create(
                                    newClient(
                                        proxy = null,
                                        sslSocketFactory = insecureSSLSocketFactory())),
                        certificatePath = PROXY_CERTIFICATE_PATH,
                        privateKeyPath = PROXY_PRIVATE_KEY_PATH,
                        credentials = credentials) to
                        newClient(
                            credentials =
                                credentials.takeUnless { error == ProxyError.UNAUTHORIZED },
                            sslSocketFactory =
                                PROXY_CLIENT_SOCKET_FACTORY to PROXY_CLIENT_TRUST_MANGER)
                else
                    Server.create(*interceptors, proxier = proxier, credentials = credentials) to
                        newClient(
                            credentials =
                                credentials.takeUnless { error == ProxyError.UNAUTHORIZED })
            server.start(PORT).use {
              client.proxyRequests(baseUrl, interceptors, error?.responseStatus)
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
            ?: fail("Failed to initialize X509 trust manager")

    private fun insecureSSLSocketFactory(): Pair<SSLSocketFactory, X509TrustManager> =
        newSSLContext(*InsecureTrustManagerFactory.INSTANCE.trustManagers).socketFactory to
            (InsecureTrustManagerFactory.INSTANCE.trustManagers.find { it is X509TrustManager }
                as? X509TrustManager
                ?: fail("Failed to initialize X.509 trust manager"))

    private fun newKeystore(heldCertificate: HeldCertificate): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
          load(null, null)
          val alias = ServerTest::class.simpleName?.lowercase()
          setCertificateEntry("$alias${"cert"}", heldCertificate.certificate)
          setKeyEntry(
              "$alias${"key"}",
              heldCertificate.keyPair.private,
              PASSWORD.toCharArray(),
              arrayOf(heldCertificate.certificate))
        }

    private fun newClient(
        proxy: Int? = PORT,
        credentials: Credentials? = null,
        sslSocketFactory: Pair<SSLSocketFactory, X509TrustManager>? = null
    ): OkHttpClient =
        OkHttpClient.Builder()
            .run { proxy?.let { proxySelector(ProxySelector.of(InetSocketAddress(it))) } ?: this }
            .run {
              credentials?.let { (username, password) ->
                proxyAuthenticator { _, response ->
                  response.request
                      .newBuilder()
                      .header("Proxy-Authorization", okhttp3.Credentials.basic(username, password))
                      .build()
                }
              }
                  ?: this
            }
            .run {
              sslSocketFactory?.let { (socketFactory, trustManager) ->
                sslSocketFactory(socketFactory, trustManager)
              }
                  ?: this
            }
            .build()

    private fun webServer(
        secure: Boolean = false,
        host: String = "localhost",
        block: (String) -> Unit
    ) {
      Javalin.create {
            if (secure)
                it.jetty.server {
                  JettyServer().apply {
                    val sslContextFactory =
                        SslContextFactory.Server().apply {
                          keyStore = newKeystore(LOCALHOST_CERTIFICATE)
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
          .use { block("http${"s".takeIf { secure }.orEmpty()}://$host:${it.port()}") }
    }

    @Suppress("TestFunctionName")
    private fun OkHttpClient.GET(url: String): String =
        OkRequest.Builder().url(url).build().let(::newCall).execute().data()

    @Suppress("TestFunctionName")
    private fun OkHttpClient.POST(url: String, data: String): String =
        OkRequest.Builder()
            .url(url)
            .method("POST", data.toRequestBody())
            .build()
            .let(::newCall)
            .execute()
            .data()

    private fun OkResponse.data(): String =
        use { it.body?.use(ResponseBody::string) } ?: fail("No response data in $this")

    private fun OkHttpClient.proxyRequests(
        baseUrl: String,
        interceptors: Array<out Interceptor>,
        responseStatus: HttpResponseStatus? = null
    ) {
      if (responseStatus == null) {
        assertEquals(TARGET_DATA, GET("$baseUrl$TARGET_PATH"))
        assertEquals(
            if (interceptors.isEmpty()) TARGET_DATA else INTERCEPTED_DATA,
            POST("$baseUrl$TARGET_PATH", TARGET_DATA))
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
                            "${HttpHeaderNames.COOKIE}",
                            newRandomString(Server.MAX_HEADER_SIZE + 1))
                    else this
                  }
                  .build()
                  .let(::newCall)
                  .execute()
                  .code)
    }

    private fun newRandomString(size: Int): String =
        with('a'..'z') { (1..size).map { random() } }.joinToString("")

    private fun exec(command: Collection<String>, readOutput: Boolean = true): String? =
        ProcessExecutor()
            .command(command)
            .readOutput(readOutput)
            .execute()
            .takeIf { readOutput }
            ?.outputUTF8()
  }
}
