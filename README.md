# proxi

[![Test](https://github.com/c-fraser/proxi/workflows/Test/badge.svg)](https://github.com/c-fraser/proxi/actions)
[![Release](https://img.shields.io/github/v/release/c-fraser/proxi?logo=github&sort=semver)](https://github.com/c-fraser/proxi/releases)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.c-fraser/proxi.svg)](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxi)
[![Javadoc](https://javadoc.io/badge2/io.github.c-fraser/proxi/javadoc.svg)](https://javadoc.io/doc/io.github.c-fraser/proxi)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

`proxi` is an HTTP(S) 1.x proxy server which enables traffic to be intercepted and dynamically
transformed.

<!--- TOC -->

* [Usage](#usage)
* [Examples](#examples)
  * [Intercept a proxied HTTP request](#intercept-a-proxied-http-request)
  * [Proxy an HTTPS request](#proxy-an-https-request)
    * [Proxy server provides trusted certificate chain](#proxy-server-provides-trusted-certificate-chain)
    * [Proxy server executes requests with mTLS](#proxy-server-executes-requests-with-mtls)
* [License](#license)
* [Acknowledgements](#acknowledgements)

<!--- END -->

## Usage

The `proxi` library is accessible
via [Maven Central](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxi).

## Examples

### Intercept a proxied HTTP request

<!--- TEST_NAME Example01Test --> 

<!--- INCLUDE
import io.github.cfraser.proxi.Interceptor
import io.github.cfraser.proxi.Response
import io.github.cfraser.proxi.Server
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.ResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetSocketAddress
import java.net.ProxySelector

fun runExample01() { 
----- SUFFIX 
}
-->

```kotlin
// Initialize a mock web server which is the target for proxy requests.
MockWebServer().use { target ->
  // Enqueue a mock response for the proxied request.
  target.enqueue(MockResponse().setBody("Hello!"))
  // Define a response interceptor to modify the proxy response.
  class ResponseInterceptor : Interceptor {
    override fun intercept(response: Response) {
      // Print the response from the proxy request.
      response.body?.let(::String)?.also { println("Intercepted: $it") }
      // Change the proxy response body.
      response.body = "Goodbye!".toByteArray()
    }
  }
  // Create and start the proxy server.
  Server.create(ResponseInterceptor()).start(8787).use {
    // Initialize an HTTP client that uses the proxy server.
    val client =
      OkHttpClient.Builder().proxySelector(ProxySelector.of(InetSocketAddress(8787))).build()
    // Execute the request then print the response body. 
    client
      .newCall(Request.Builder().url(target.url("/hello")).build())
      .execute()
      .use { response -> response.body?.use(ResponseBody::string) }
      ?.also { println("Received: $it") }
  }
}
```

```text
Intercepted: Hello!
Received: Goodbye!
```

<!--- KNIT Example01.kt -->
<!--- TEST -->

### Proxy an HTTPS request

#### Proxy server provides trusted certificate chain

> This example code is intended to be representative of a realistic HTTPS deployment.

<!--- TEST_NAME Example02Test --> 

<!--- INCLUDE
import io.github.cfraser.proxi.Server
import io.github.cfraser.proxi.ServerTest.Companion.inFile
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.InetSocketAddress
import java.net.ProxySelector

fun runExample02() { 
----- SUFFIX 
}
-->

```kotlin
// Create a root certificate authority.
val rootCertificate = HeldCertificate.Builder().certificateAuthority(1).rsa2048().build()
// Create an intermediate certificate authority (signed by the root certificate).
val intermediateCertificate =
  HeldCertificate.Builder().certificateAuthority(0).signedBy(rootCertificate).rsa2048().build()
// Ensure the client trusts the root certificate.
val clientCertificates =
  HandshakeCertificates.Builder().addTrustedCertificate(rootCertificate.certificate).build()
// Create and start the proxy server which uses the intermediate certificate authority to generate
// trusted certificates for the (destination of) proxy requests.
Server.create(
  // To proxy HTTPS requests the proxy server requires a CA certificate and private key.
  // This is required because the client must trust the (generated) proxy server
  // certificate to be able to decrypt and proxy the HTTPS request.
  certificatePath = intermediateCertificate.certificatePem().inFile("proxy.pem"),
  privateKeyPath = intermediateCertificate.privateKeyPkcs8Pem().inFile("proxy.key")
)
  .start(8787)
  .use {
    // Initialize an HTTPS client that uses the proxy server and trusts the root certificate.
    val client =
      OkHttpClient.Builder()
        .proxySelector(ProxySelector.of(InetSocketAddress(8787)))
        .sslSocketFactory(
          clientCertificates.sslSocketFactory(), clientCertificates.trustManager
        )
        .build()
    // Execute an HTTPS request and expect a successful response code.
    client
      .newCall(Request.Builder().url("https://httpbin.org/get").build())
      .execute()
      .use(Response::isSuccessful)
      .also(::println)
  }
```

<!--- KNIT Example02.kt -->
<!--- TEST
true
-->

#### Proxy server executes requests with mTLS

<!--- TEST_NAME Example03Test --> 

<!--- INCLUDE
import io.github.cfraser.proxi.Proxier
import io.github.cfraser.proxi.Server
import io.github.cfraser.proxi.ServerTest
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProxySelector

fun runExample03() { 
----- SUFFIX 
}
-->

```kotlin
// Create a (self-signed) certificate (and private key) for the (local) mock web server.
val certificate = ServerTest.LOCALHOST_CERTIFICATE
// Use the certificate for the TLS handshake between the client and mock web server.
val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
// Ensure the client trusts the certificate used by the mock web server.
val clientCertificates =
  HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
// Initialize a "secure" mock web server which is the target for proxy requests.
MockWebServer()
  // Specify the mock web server certificates to use to serve HTTPS requests.
  .apply { useHttps(serverCertificates.sslSocketFactory(), false) }
  .use { target ->
    // Enqueue a mock response for the proxied request.
    target.enqueue(MockResponse())
    // Create a proxier that uses the client certificates.
    val proxier =
      Proxier.create(
        OkHttpClient.Builder()
          .sslSocketFactory(
            clientCertificates.sslSocketFactory(), clientCertificates.trustManager
          )
          .build()
      )
    // Create and start the proxy server that can connect to the "secure" mock web server.
    Server.create(
      proxier = proxier,
      // Provide the certificate and private key to proxy HTTPS requests.
      certificatePath = ServerTest.PROXY_CERTIFICATE_PATH,
      privateKeyPath = ServerTest.PROXY_PRIVATE_KEY_PATH
    )
      .start(8787)
      .use {
        // Initialize an HTTPS client that uses the proxy server and trusts its certificate.
        val client =
          OkHttpClient.Builder()
            .proxySelector(ProxySelector.of(InetSocketAddress(8787)))
            .sslSocketFactory(
              ServerTest.PROXY_CLIENT_SOCKET_FACTORY,
              ServerTest.PROXY_CLIENT_TRUST_MANGER
            )
            .build()
        // Execute an HTTPS the request to the target and expect response to be successful.
        client
          .newCall(Request.Builder().url(target.url("/")).build())
          .execute()
          .use(Response::isSuccessful)
          .let(::println)
      }
  }
```

<!--- KNIT Example03.kt -->
<!--- TEST
true
-->

## License

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

## Acknowledgements

Kudos to the [proxyee](https://github.com/monkeyWie/proxyee) project which significantly influenced
the implementation of `proxi`.
