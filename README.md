# proxi

[![Test](https://github.com/c-fraser/proxi/workflows/Test/badge.svg)](https://github.com/c-fraser/proxi/actions)
[![Release](https://img.shields.io/github/v/release/c-fraser/proxi?logo=github&sort=semver)](https://github.com/c-fraser/proxi/releases)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.c-fraser/proxi.svg)](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxi)
[![Javadoc](https://javadoc.io/badge2/io.github.c-fraser/proxi/javadoc.svg)](https://javadoc.io/doc/io.github.c-fraser/proxi)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

`proxi` is an HTTP(S) 1.x proxy server which enables traffic to be intercepted and dynamically
transformed.

## Usage

The `proxi` library is accessible
via [Maven Central](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxi).

## Example

The example (Kotlin) code below demonstrates how to make a request to an "external" API
then intercept the response.

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
      response.body?.let(::String).also(::println)
      // Change the proxy response body.
      response.body = "Goodbye!".toByteArray()
    }
  }
  // Create and start the proxy server.
  Server.create(ResponseInterceptor()).start(8787).use {
    // Initialize an HTTP client that uses the proxy server.
    val client =
      OkHttpClient.Builder().proxySelector(ProxySelector.of(InetSocketAddress(8787))).build()
    // The HTTP request to the target, which will be proxied by server.
    val request = Request.Builder().url(target.url("/hello")).build()
    // Execute the request then print the response.
    client.newCall(request).execute().use { response ->
      response.body?.use(ResponseBody::string)?.also(::println)
    }
  }
}
```

```text
Hello!
Goodbye!
```

<!--- KNIT Example01.kt -->
<!--- TEST -->

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
