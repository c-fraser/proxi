# proxylin

[![Test](https://github.com/c-fraser/proxylin/workflows/Test/badge.svg)](https://github.com/c-fraser/proxylin/actions)
[![Release](https://img.shields.io/github/v/release/c-fraser/proxylin?logo=github&sort=semver)](https://github.com/c-fraser/proxylin/releases)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.c-fraser/proxylin.svg)](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxylin)
[![Javadoc](https://javadoc.io/badge2/io.github.c-fraser/proxylin/javadoc.svg)](https://javadoc.io/doc/io.github.c-fraser/proxylin)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

`proxylin` is a [javalin](https://javalin.io/) plugin enabling (forward) proxying capabilities.

<!--- TOC -->

* [Usage](#usage)
* [Example](#example)
* [License](#license)
* [Acknowledgements](#acknowledgements)

<!--- END -->

## Usage

The `proxylin` library is accessible
via [Maven Central](https://search.maven.org/search?q=g:io.github.c-fraser%20AND%20a:proxylin).

## Example

The example (Kotlin) code below demonstrates how to make a request to an "external" API
then intercept the response.

<!--- TEST_NAME Example01Test --> 

<!--- INCLUDE
import io.github.cfraser.proxylin.Proxylin
import io.github.cfraser.proxylin.Response
import io.javalin.Javalin
import okhttp3.ResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.util.function.Consumer
import okhttp3.OkHttpClient.Builder as OkHttpClientBuilder
import okhttp3.Request.Builder as RequestBuilder

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
  val interceptor =
    Consumer<Response> { response ->
      // Print the response from the proxy request.
      response.body?.let(::String).also(::println)
      // Change the proxy response body.
      response.body = "Goodbye!".toByteArray()
    }
  // Initialize the `proxylin` plugin.
  val plugin = Proxylin.create(onResponse = interceptor)
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

Kudos to the [javalin](https://github.com/javalin/javalin) project for making `proxylin` possible.
