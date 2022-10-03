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

import io.javalin.Javalin
import io.ktor.network.tls.certificates.generateCertificate
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.io.path.inputStream
import kotlin.io.path.outputStream
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
import org.junit.jupiter.api.io.TempDir

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
    verifyServer(credentials = Credentials(USERNAME, PASSWORD), authorized = false)
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
  fun `proxy an HTTPS request`() {
    verifyServer(secure = true)
  }

  @Test
  fun `proxy an authorized HTTPS request`() {
    verifyServer(secure = true, credentials = Credentials(USERNAME, PASSWORD))
  }

  @Test
  fun `unauthorized HTTPS request is not proxied`() {
    verifyServer(secure = true, credentials = Credentials(USERNAME, PASSWORD), authorized = false)
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

  private companion object {

    const val PORT = 8787
    const val TARGET_PATH = "/external"
    const val TARGET_DATA = "external"
    const val INTERCEPTED_DATA = "intercepted"
    const val USERNAME = "test-user"
    const val PASSWORD = "p@\$sW0rD"

    @JvmStatic @TempDir @Suppress("VarCouldBeVal") lateinit var DIRECTORY: Path

    val PROXY_CERTIFICATE by
        lazy<Path> { DIRECTORY.resolve("proxy.pem").apply { writeResource("cert.pem") } }
    val PROXY_PRIVATE_KEY by
        lazy<Path> { DIRECTORY.resolve("proxy.der").apply { writeResource("cert.key") } }
    val CLIENT_TRUSTSTORE by lazy { newTruststore(PROXY_CERTIFICATE) }
    val CLIENT_TRUST_MANGER by lazy { newX509TrustManager(CLIENT_TRUSTSTORE) }
    val CLIENT_SOCKET_FACTORY by
        lazy<SSLSocketFactory> { newSSLContext(CLIENT_TRUST_MANGER).socketFactory }

    fun verifyServer(
        vararg interceptors: Interceptor,
        secure: Boolean = false,
        credentials: Credentials? = null,
        authorized: Boolean = true
    ) {
      webServer(secure = secure) { baseUrl ->
        if (secure)
            Server.create(
                    *interceptors,
                    proxier =
                        Proxier.create(
                            newClient(proxy = null, sslSocketFactory = insecureSSLSocketFactory())),
                    certificatePath = PROXY_CERTIFICATE,
                    privateKeyPath = PROXY_PRIVATE_KEY,
                    credentials = credentials)
                .apply { start(PORT) }
                .use {
                  newClient(sslSocketFactory = CLIENT_SOCKET_FACTORY to CLIENT_TRUST_MANGER)
                      .proxyRequests(baseUrl, interceptors, credentials, authorized)
                }
        else
            Server.create(*interceptors, credentials = credentials).start(PORT).use {
              newClient().proxyRequests(baseUrl, interceptors, credentials, authorized)
            }
      }
    }

    fun newSSLContext(vararg trustManagers: TrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, trustManagers, null) }

    fun newTruststore(trustedCertificate: Path): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
          load(null, null)
          val factory = CertificateFactory.getInstance("X.509")
          val certificate =
              trustedCertificate.inputStream().buffered().use(factory::generateCertificate)
          setCertificateEntry(Server::class.simpleName?.lowercase(), certificate)
        }

    fun newX509TrustManager(truststore: KeyStore): X509TrustManager =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(truststore) }
            .trustManagers
            .firstOrNull() as? X509TrustManager
            ?: error("Failed to initialize X509 trust manager")

    fun insecureSSLSocketFactory(): Pair<SSLSocketFactory, X509TrustManager> =
        newSSLContext(*InsecureTrustManagerFactory.INSTANCE.trustManagers).socketFactory to
            (InsecureTrustManagerFactory.INSTANCE.trustManagers.find { it is X509TrustManager }
                as? X509TrustManager
                ?: fail("Failed to initialize X.509 trust manager"))

    fun Path.writeResource(name: String) {
      ServerTest::class.java.classLoader.getResourceAsStream(name)?.also {
        outputStream().use(it::copyTo)
      }
    }

    fun newClient(
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

    fun webServer(secure: Boolean = false, block: (String) -> Unit) {
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

    fun OkHttpClient.get(url: String, credentials: Credentials?): String =
        OkRequest.Builder()
            .url(url)
            .credentials(credentials)
            .build()
            .let(::newCall)
            .execute()
            .data()

    fun OkHttpClient.post(url: String, data: String, credentials: Credentials?): String =
        OkRequest.Builder()
            .url(url)
            .method("POST", data.toRequestBody())
            .credentials(credentials)
            .build()
            .let(::newCall)
            .execute()
            .data()

    fun OkRequest.Builder.credentials(credentials: Credentials?): OkRequest.Builder =
        credentials?.let { (username, password) ->
          header("Proxy-Authorization", OkCredentials.basic(username, password))
        }
            ?: this

    fun OkResponse.data(): String =
        use { it.body?.use(ResponseBody::string) } ?: fail("No response data in $this")

    fun OkHttpClient.proxyRequests(
        baseUrl: String,
        interceptors: Array<out Interceptor>,
        credentials: Credentials?,
        authorized: Boolean
    ) {
      if (authorized) {
        assertEquals(TARGET_DATA, get("$baseUrl$TARGET_PATH", credentials))
        assertEquals(
            if (interceptors.isEmpty()) TARGET_DATA else INTERCEPTED_DATA,
            post("$baseUrl$TARGET_PATH", TARGET_DATA, credentials))
      } else
          assertEquals(
              401,
              OkRequest.Builder().url("$baseUrl$TARGET_PATH").build().let(::newCall).execute().code)
    }
  }
}
