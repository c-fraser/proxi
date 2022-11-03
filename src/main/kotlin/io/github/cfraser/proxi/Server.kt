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

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.DecoderException
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.DefaultHttpHeaders
import io.netty.handler.codec.http.EmptyHttpHeaders
import io.netty.handler.codec.http.FullHttpRequest
import io.netty.handler.codec.http.FullHttpResponse
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpObjectDecoder
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.codec.http.HttpUtil
import io.netty.handler.codec.http.HttpVersion
import io.netty.handler.codec.http.TooLongHttpHeaderException
import io.netty.handler.codec.http.TooLongHttpLineException
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.util.NetUtil
import io.netty.util.ReferenceCountUtil
import java.io.Closeable
import java.math.BigInteger
import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Path
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.Year
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.Date
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.bufferedReader
import kotlin.math.max
import kotlin.properties.Delegates.notNull
import kotlin.properties.Delegates.observable
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * [Server] is an intercepting HTTP(S) proxy which enables received [Request] and [Response] data to
 * be transformed dynamically.
 */
class Server private constructor(private val initializer: ChannelInitializer<Channel>) : Closeable {

  private val started = AtomicBoolean()
  private val stopped = AtomicBoolean()

  private val acceptorGroup by lazy<EventLoopGroup> { NioEventLoopGroup() }
  private val workerGroup by lazy<EventLoopGroup> { NioEventLoopGroup() }
  private var channel by notNull<Channel>()

  /**
   * Synchronously start the proxy [Server] on the [port].
   *
   * @throws Exception if the proxy server failed to start
   * @return `this` started [Server] instance
   */
  @Throws(Exception::class)
  fun start(port: Int): Server = apply {
    check(started.compareAndSet(false, true)) { "The proxy server was already started" }
    LOGGER.info("Starting proxy server on port {}", port)
    channel =
        ServerBootstrap()
            .group(acceptorGroup, workerGroup)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(initializer)
            .bind(port)
            .sync()
            .run { if (isSuccess) channel() else throw cause() }
  }

  /**
   * Synchronously stop the proxy [Server].
   *
   * @throws Exception if the proxy server failed to stop
   * @return `this` stopped [Server] instance
   */
  @Throws(Exception::class)
  fun stop(): Server = apply {
    check(started.get()) { "The proxy server is not running" }
    check(stopped.compareAndSet(false, true)) { "The proxy server was already stopped" }
    LOGGER.info("Stopping proxy server")
    channel.close().sync().apply { if (!isSuccess) throw cause() }
    fun EventLoopGroup.close() =
        takeUnless { it.isShuttingDown || it.isShutdown || it.isTerminated }?.shutdownGracefully()
    acceptorGroup.close()
    workerGroup.close()
  }

  /**
   * Synchronously [stop] the proxy [Server].
   *
   * @see stop for details about stopping the proxy server
   */
  override fun close() {
    stop()
  }

  companion object {

    /**
     * Create a proxy [Server] instance.
     *
     * The [interceptors] are used to dynamically transform intercepted [Request] and [Response]
     * data. When a [Request] is received by the proxy [Server] it is associated with an
     * [Interceptor] by finding the **first**, respective to the given order, that determines the
     * [Request] to be [Interceptor.interceptable]. If the [Request] is not *interceptable*, then a
     * default *no-op* [Interceptor] is used.
     *
     * For the proxy [Server] to support proxying *HTTPS* requests, the [certificatePath] and
     * [privateKeyPath] must be provided. This enables the server to decrypt the proxied requests
     * and responses for interception, assuming the client correctly trusts the certificate at the
     * given [certificatePath].
     *
     * @param interceptors the [Array] of [Interceptor] to use to intercept proxy requests and
     * responses. The first [Interceptor], relative to the given order, that is
     * [Interceptor.interceptable] is used for each proxy request
     * @param proxier the *global* [Proxier] to use to execute proxy requests. The *global*
     * [Proxier] may be overridden by a specific [Request] through an [Interceptor.proxier].
     * @param executor the [ExecutorService] to use to asynchronously execute proxy requests. The
     * asynchronous execution also includes interception of the proxy request and response.
     * @param certificatePath the [Path] to the X.509 *trusted certificate authority*
     * @param privateKeyPath the [Path] to the PKCS8 private key for the *trusted certificate*
     * @param credentials the [Credentials] required in the `proxy-authorization` header
     * @return the proxy [Server]
     * @throws RuntimeException if the proxy server failed to initialize
     */
    @JvmStatic
    @JvmOverloads
    fun create(
        vararg interceptors: Interceptor,
        proxier: Proxier? = null,
        executor: ExecutorService? = null,
        certificatePath: Path? = null,
        privateKeyPath: Path? = null,
        credentials: Credentials? = null,
    ): Server =
        Server(
            Initializer(
                interceptors.toList(),
                proxier ?: Proxier.create(),
                executor
                    ?: Executors.newFixedThreadPool(
                        max(Runtime.getRuntime().availableProcessors(), 64)),
                certificatePath?.readX509Certificate(),
                privateKeyPath?.readPrivateKey(),
                credentials))

    private val LOGGER: Logger = LoggerFactory.getLogger(Server::class.java)

    /** Read the X.509 certificate at the [Path]. */
    private fun Path.readX509Certificate(): X509CertificateHolder =
        when (val parsed = parse()) {
          is X509CertificateHolder -> parsed
          else -> error("Failed to parse certificate")
        }

    /** Read the PKCS8 private key at the [Path]. */
    private fun Path.readPrivateKey(): PrivateKeyInfo =
        when (val parsed = parse()) {
          is PrivateKeyInfo -> parsed
          is PEMKeyPair -> parsed.privateKeyInfo
          else -> error("Failed to parse private key")
        }

    /** Parse the certificate at the [Path] with a [PEMParser]. */
    private fun Path.parse(): Any =
        PEMParser(bufferedReader(Charsets.US_ASCII)).use(PEMParser::readObject)

    internal const val MAX_URI_SIZE = HttpObjectDecoder.DEFAULT_MAX_INITIAL_LINE_LENGTH
    internal const val MAX_HEADER_SIZE = HttpObjectDecoder.DEFAULT_MAX_HEADER_SIZE
  }

  /**
   * [Initializer] is a [ChannelInitializer] which initializes the [Channel] with the
   * [HttpServerCodec], [HttpObjectAggregator], and [Handler].
   */
  private class Initializer(
      private val interceptors: List<Interceptor>,
      private val proxier: Proxier,
      private val executor: ExecutorService,
      certificate: X509CertificateHolder?,
      privateKey: PrivateKeyInfo?,
      private val credentials: Credentials?,
  ) : ChannelInitializer<Channel>() {

    /** The [Certificates] shared by the initialized [Handler] instances. */
    private val certificates =
        certificate?.let { privateKey?.let { Certificates(certificate, privateKey) } }

    override fun initChannel(ch: Channel) {
      ch.pipeline()
          .addFirst(
              HTTP_SERVER_CODEC,
              HTTP_OBJECT_AGGREGATOR,
              Handler(interceptors, proxier, executor, certificates, credentials))
    }

    companion object {

      /** Get a [HttpServerCodec] instance. */
      val HTTP_SERVER_CODEC: HttpServerCodec
        get() =
            HttpServerCodec(MAX_URI_SIZE, MAX_HEADER_SIZE, HttpObjectDecoder.DEFAULT_MAX_CHUNK_SIZE)

      /** Get a [HttpObjectAggregator] instance. */
      val HTTP_OBJECT_AGGREGATOR: HttpObjectAggregator
        get() = HttpObjectAggregator(/* 8 MiB */ 8 * 1024 * 1024)
    }
  }

  /**
   * [Handler] in a [ChannelInboundHandlerAdapter] which handles the proxying of received
   * [HttpRequest] data.
   */
  private class Handler(
      private val interceptors: List<Interceptor>,
      private val proxier: Proxier,
      private val executor: ExecutorService,
      private val certificates: Certificates?,
      private val credentials: Credentials?,
  ) : ChannelInboundHandlerAdapter() {

    /** The [host] and [port] of the proxy request [Destination]. */
    private data class Destination(val host: String, val port: Int)
    private var destination by
        observable<Destination?>(null) { _, _, destination ->
          LOGGER.debug("Proxying requests to {}", destination)
        }

    /**
     * The [Future] denoting the completion of the *current* proxy request processing.
     *
     * > The [future] is intended to prevent (proxy response) writes to a closed channel.
     */
    private var future: Future<*>? = null

    @Suppress("TooGenericExceptionCaught")
    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
      when (msg) {
        is HttpRequest ->
            try {
              msg.checkDecoded()
              when {
                msg.method() == HttpMethod.CONNECT -> {
                  destination = msg.parseDestination()
                  ctx.connect()
                }
                msg is FullHttpRequest -> {
                  msg.checkAuthorized()
                  val request = msg.asRequest()
                  val keepAlive = HttpUtil.isKeepAlive(msg)
                  future =
                      executor.submit {
                        try {
                          val response = request.proxy()
                          LOGGER.debug("Writing proxy response {}", response)
                          ctx.writeResponse(response, keepAlive)
                        } catch (error: Error) {
                          LOGGER.error("Failed to proxy request", error)
                          ctx.handleError(error)
                        }
                      }
                }
                else -> throw UnexpectedType(msg)
              }
            } catch (error: Error) {
              LOGGER.error("Unable to proxy request", error)
              ctx.handleError(error)
            } finally {
              ReferenceCountUtil.release(msg)
            }
        is ByteBuf ->
            try {
              val sslCtx = msg.initializeSSL()
              ctx.connectHttps(sslCtx, msg)
            } catch (error: Error) {
              LOGGER.error("Unable to initialize HTTPS connection", error)
              ReferenceCountUtil.release(msg)
              ctx.handleError(error)
            }
      }
    }

    override fun channelUnregistered(ctx: ChannelHandlerContext?) {
      try {
        future?.get(1, TimeUnit.SECONDS)
      } catch (_: ExecutionException) {
        future?.cancel(true)
      }
      ctx?.channel()?.close()
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun exceptionCaught(ctx: ChannelHandlerContext?, cause: Throwable?) {
      LOGGER.warn("Uncaught exception", cause)
    }

    /**
     * Parse the [Destination] from the [HttpRequest.uri].
     *
     * @throws HttpsUnsupported if the server was created without a certificate and private key
     * @throws InvalidUri if the [HttpRequest.uri] is not a `host:port`
     * @throws InvalidHost if the parsed host is an IP(v4) address (instead of a hostname)
     * @throws InvalidPort if the parsed port is not an [Int]
     */
    private fun HttpRequest.parseDestination(): Destination {
      if (certificates == null) throw HttpsUnsupported
      val (host, port) =
          uri().split(':', limit = 2).takeIf { it.size == 2 } ?: throw InvalidUri(uri())
      return Destination(
          host.takeUnless { NetUtil.isValidIpV4Address(it) } ?: throw InvalidHost(host),
          port.toIntOrNull() ?: throw InvalidPort(port))
    }

    /**
     * Check if the [HttpRequest] contains the [HttpHeaderNames.PROXY_AUTHORIZATION] header matching
     * the [credentials].
     *
     * @throws Unauthorized if the [HttpRequest] does not contain the proxy [credentials]
     */
    private fun HttpRequest.checkAuthorized() {
      if (credentials != null &&
          credentials !=
              headers()[HttpHeaderNames.PROXY_AUTHORIZATION]
                  ?.takeIf { it.startsWith("Basic ") }
                  ?.removePrefix("Basic ")
                  ?.let { Base64.getDecoder().decode(it).decodeToString() }
                  ?.split(':', limit = 2)
                  ?.let { (username, password) -> Credentials(username, password) })
          throw Unauthorized
    }

    /**
     * Convert the [FullHttpRequest] to a proxy [Request].
     *
     * @throws InvalidDestination if the destination URL is malformed
     */
    private fun FullHttpRequest.asRequest(): Request {
      val destination = destination?.run { "https://$host:$port${uri()}" } ?: uri()
      return Request(
          try {
            URI(destination)
          } catch (_: URISyntaxException) {
            throw InvalidDestination(destination)
          },
          method().name(),
          buildMap {
            headers().associateTo(this) { (key, value) -> key to value }
            remove("${HttpHeaderNames.PROXY_AUTHORIZATION}")
          },
          ByteBufUtil.getBytes(content()))
    }

    /**
     * Proxy the [Request] with an [Interceptor] and [Proxier].
     *
     * > The [NoOpInterceptor] is used if none of the [interceptors] determine the [Request] is
     * [Interceptor.interceptable].
     *
     * @throws FindInterceptorFailure if any [Interceptor.interceptable] check throws an exception
     * @throws RequestInterceptFailure if the [Interceptor] fails to intercept the [Request]
     * @throws ProxierFailure if the [Proxier] fails to execute the [Request]
     * @throws ResponseInterceptFailure if the [Interceptor] fails to intercept the [Response]
     */
    private fun Request.proxy(): Response {
      val interceptor =
          runCatching { interceptors.find { it.interceptable(this) } }
              .map { it ?: NoOpInterceptor }
              .getOrElse { throw FindInterceptorFailure(it) }
      LOGGER.debug("Proxying request {} with {}", this, interceptor)
      return runCatching { also(interceptor::intercept) }
          .onFailure { throw RequestInterceptFailure(it) }
          .mapCatching((interceptor.proxier ?: proxier)::execute)
          .onFailure { throw ProxierFailure(it) }
          .mapCatching { it.also(interceptor::intercept) }
          .getOrElse { throw ResponseInterceptFailure(it) }
    }

    /**
     * Initialize a [SslContext] for the [destination], using the [certificates], from the [ByteBuf]
     * which is expected to be a [TLS_HANDSHAKE] 'client hello' message.
     *
     * @throws ExpectedTLSHandshake if the first [Byte] in the [ByteBuf] is not [TLS_HANDSHAKE]
     * @throws HttpsUnsupported if the server was created without a certificate and private key
     * @throws UnknownDestination if the [destination] is `null`
     * @throws CertificateGenerationFailure if the certificate chain could not be generated
     */
    private fun ByteBuf.initializeSSL(): SslContext {
      if (getByte(0) != TLS_HANDSHAKE) throw ExpectedTLSHandshake
      if (certificates == null) throw HttpsUnsupported
      val destination = destination?.host ?: throw UnknownDestination
      LOGGER.debug("Initializing SSL context for {}", destination)
      val certificate =
          @Suppress("TooGenericExceptionCaught")
          try {
            certificates[destination]
          } catch (throwable: Throwable) {
            throw CertificateGenerationFailure(throwable)
          }
      return SslContextBuilder.forServer(
              certificates.privateKey, certificate, certificates.certificate)
          .build()
    }

    /** The errors that can occur while proxying a request within the [Handler.channelRead]. */
    private sealed class Error(message: String, cause: Throwable? = null) :
        RuntimeException(message, cause)
    private class DecodeFailure(cause: DecoderException) :
        Error("Failed to decode HTTP request", cause)
    private object HttpsUnsupported : Error("Certificate and private key required for HTTPS")
    private class InvalidUri(uri: String) : Error("Invalid URI $uri")
    private class InvalidHost(host: String) : Error("Invalid host $host")
    private class InvalidPort(port: String) : Error("Invalid port $port")
    private class InvalidDestination(destination: String) : Error("Invalid URI $destination")
    private class UnexpectedType(msg: Any) : Error("Read unexpected type ${msg::class.simpleName}")
    private object Unauthorized : Error("Unauthorized proxy request")
    private class FindInterceptorFailure(cause: Throwable) :
        Error("Unable to find interceptor", cause)
    private class RequestInterceptFailure(cause: Throwable) :
        Error("Failed to intercept request", cause)
    private class ResponseInterceptFailure(cause: Throwable) :
        Error("Failed to intercept response", cause)
    private class ProxierFailure(cause: Throwable) :
        Error("Failed to execute proxy request", cause)
    private object ExpectedTLSHandshake : Error("Expected TLS 'client hello' message")
    private object UnknownDestination : Error("Unknown destination")
    private class CertificateGenerationFailure(cause: Throwable) :
        Error("Failed to generate certificate", cause)

    /**
     * A no-op [Interceptor] which is used if a [Request] does not match any of the [interceptors].
     */
    private object NoOpInterceptor : Interceptor {
      override fun toString() = "(default) no-op interceptor"
    }

    private companion object {

      val LOGGER: Logger = LoggerFactory.getLogger(Handler::class.java)

      /**
       * [TLS_HANDSHAKE] is the first [Byte] of the initial TLS handshake message (client hello).
       */
      const val TLS_HANDSHAKE: Byte = 22

      /**
       * Check the if the [HttpRequest] was decoded successfully.
       *
       * @throws DecodeFailure if the [HttpRequest] was not decoded successfully
       */
      fun HttpRequest.checkDecoded() {
        decoderResult()
            .takeIf { it.isFailure }
            ?.cause()
            ?.let { it as? DecoderException }
            ?.also { throw DecodeFailure(it) }
      }

      /**
       * Write a [FullHttpResponse] with the [status] and [content] using the
       * [ChannelHandlerContext].
       */
      fun ChannelHandlerContext.writeResponse(
          status: HttpResponseStatus,
          content: String?,
          keepAlive: Boolean
      ) {
        writeResponse(
            status,
            Unpooled.copiedBuffer(content.orEmpty(), Charsets.UTF_8),
            DefaultHttpHeaders(),
            keepAlive)
      }

      /** Write the [response] as a [FullHttpResponse] using the [ChannelHandlerContext]. */
      fun ChannelHandlerContext.writeResponse(response: Response, keepAlive: Boolean) {
        writeResponse(
            HttpResponseStatus.valueOf(response.statusCode),
            response.body?.let(Unpooled::copiedBuffer) ?: Unpooled.EMPTY_BUFFER,
            DefaultHttpHeaders().apply { response.headers.forEach(::add) },
            keepAlive)
      }

      /**
       * Write a [FullHttpResponse] with the [status], [content], and [headers] using the
       * [ChannelHandlerContext].
       *
       * > Add the [ChannelFutureListener.CLOSE] listener if [keepAlive] is `false`.
       */
      fun ChannelHandlerContext.writeResponse(
          status: HttpResponseStatus,
          content: ByteBuf,
          headers: DefaultHttpHeaders,
          keepAlive: Boolean
      ) {
        writeAndFlush(
                DefaultFullHttpResponse(
                        HttpVersion.HTTP_1_1, status, content, headers, EmptyHttpHeaders.INSTANCE)
                    .also {
                      HttpUtil.setContentLength(it, it.content().readableBytes().toLong())
                      HttpUtil.setKeepAlive(it, keepAlive)
                    })
            .also { if (!keepAlive) it.addListener(ChannelFutureListener.CLOSE) }
      }

      /**
       * Write the response to the [HttpMethod.CONNECT] request and prepare the [Channel.pipeline]
       * for the TLS 'client hello' message.
       */
      fun ChannelHandlerContext.connect() {
        writeResponse(HttpResponseStatus.OK, null, true)
        channel().pipeline().remove(HttpServerCodec::class.java)
        channel().pipeline().remove(HttpObjectAggregator::class.java)
      }

      /**
       * Establish an HTTPS connection with [context] by adding the [SslContext.newHandler],
       * [Initializer.HTTP_SERVER_CODEC], and [Initializer.HTTP_OBJECT_AGGREGATOR] to the
       * [Channel.pipeline].
       */
      fun ChannelHandlerContext.connectHttps(context: SslContext, msg: ByteBuf) {
        pipeline()
            .addFirst(
                context.newHandler(alloc()),
                Initializer.HTTP_SERVER_CODEC,
                Initializer.HTTP_OBJECT_AGGREGATOR)
        pipeline().fireChannelRead(msg)
      }

      /**
       * Handle the [error].
       *
       * Write a [FullHttpResponse] with an appropriate [HttpResponseStatus] and [Error.message]
       * then [Channel.close] the [ChannelHandlerContext.channel].
       */
      fun ChannelHandlerContext.handleError(error: Error) {
        writeResponse(
            when (error) {
              is DecodeFailure ->
                  when (error.cause) {
                    is TooLongHttpLineException -> HttpResponseStatus.REQUEST_URI_TOO_LONG
                    is TooLongHttpHeaderException ->
                        HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
                    else -> HttpResponseStatus.BAD_REQUEST
                  }
              is InvalidUri,
              is InvalidHost,
              is InvalidPort, -> HttpResponseStatus.BAD_REQUEST
              is InvalidDestination,
              is UnexpectedType, -> HttpResponseStatus.UNPROCESSABLE_ENTITY
              Unauthorized -> HttpResponseStatus.UNAUTHORIZED
              is FindInterceptorFailure,
              is RequestInterceptFailure,
              is ResponseInterceptFailure -> HttpResponseStatus.INTERNAL_SERVER_ERROR
              is ProxierFailure -> HttpResponseStatus.BAD_GATEWAY
              HttpsUnsupported,
              ExpectedTLSHandshake,
              UnknownDestination,
              is CertificateGenerationFailure, -> HttpResponseStatus.NOT_IMPLEMENTED
            },
            error.message,
            when (error) {
              is RequestInterceptFailure,
              is ResponseInterceptFailure,
              is ProxierFailure -> true
              else -> false
            })
      }
    }
  }

  /**
   * [Certificates] generates and caches a certificate chain which is used to build the SSL context
   * for a proxy connection.
   */
  private class Certificates(certificateHolder: X509CertificateHolder, keyInfo: PrivateKeyInfo) {

    private val subject = certificateHolder.subject
    private val publicKey = certificateHolder.subjectPublicKeyInfo.toPublicKey()
    private val signatureAlgorithm = publicKey.signatureAlgorithm()

    val certificate = certificateHolder.toX509Certificate()
    val privateKey = keyInfo.toPrivateKey()

    /**
     * The [LoadingCache] that stores a generated certificate chain for a *secure* proxy connection
     * to a host.
     */
    private val cache: LoadingCache<String, X509Certificate> =
        Caffeine.newBuilder()
            .maximumSize(64)
            .evictionListener<String, X509Certificate> { host, _, cause ->
              LOGGER.debug("Generated certificate for {} removed from cache ({})", host, cause)
            }
            .build(::generate)

    /** Get the [X509Certificate], for the [host], from the [cache]. */
    operator fun get(host: String): X509Certificate = cache[host]

    /**
     * Generate a certificate chain for the [host] using the [subject], [publicKey], and
     * [privateKey] of the [certificate].
     */
    private fun generate(host: String): X509Certificate {
      LOGGER.debug("Generating certificate for {}", host)
      val certificateBuilder =
          JcaX509v3CertificateBuilder(
                  subject,
                  BigInteger(64, SecureRandom()),
                  Date.from(Instant.now().atZone(ZoneId.systemDefault()).minusDays(1).toInstant()),
                  Date.from(
                      Year.now()
                          .plus(1, ChronoUnit.YEARS)
                          .atDay(1)
                          .atStartOfDay(ZoneId.systemDefault())
                          .toInstant()),
                  X500Name("CN=$host"),
                  publicKey)
              .addExtension(
                  Extension.subjectAlternativeName,
                  true,
                  GeneralNames.getInstance(DERSequence(GeneralName(GeneralName.dNSName, host))))
              .addExtension(
                  Extension.extendedKeyUsage, true, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
      val signer = JcaContentSignerBuilder(signatureAlgorithm).build(privateKey)
      return certificateBuilder.build(signer).toX509Certificate()
    }

    @Suppress("NOTHING_TO_INLINE")
    companion object {

      val LOGGER: Logger = LoggerFactory.getLogger(Certificates::class.java)

      /** The [BouncyCastleProvider] to use to generate certificates. */
      private val BOUNCY_CASTLE_PROVIDER by lazy {
        BouncyCastleProvider().also { Security.addProvider(it) }
      }

      /** The [JcaPEMKeyConverter] to use to convert public and private keys. */
      private val KEY_CONVERTER by lazy { JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER) }

      /** The [JcaX509CertificateConverter] to use to convert X.509 certificates. */
      private val CERTIFICATE_CONVERTER by lazy {
        JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE_PROVIDER)
      }

      /**
       * Determine the signature algorithm, from the [PublicKey], to use to sign the generated
       * certificate.
       *
       * @see org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
       */
      private inline fun PublicKey.signatureAlgorithm(): String =
          checkNotNull(
              when (algorithm) {
                "ECDSA" ->
                    (this as? ECPublicKey)?.run {
                      when (params.curve.field.fieldSize) {
                        224 -> "SHA224WITHECDSA"
                        256 -> "SHA256WITHECDSA"
                        384 -> "SHA384WITHECDSA"
                        512 -> "SHA512WITHECDSA"
                        else -> null
                      }
                    }
                "RSA" -> "SHA256WITHRSAENCRYPTION"
                else -> null
              }) {
                "Unsupported private key algorithm $algorithm"
              }

      /** Convert the [SubjectPublicKeyInfo] to a [PublicKey] using the [KEY_CONVERTER]. */
      private inline fun SubjectPublicKeyInfo.toPublicKey(): PublicKey =
          KEY_CONVERTER.getPublicKey(this)

      /** Convert the [PrivateKeyInfo] to a [PrivateKey] using the [KEY_CONVERTER]. */
      private inline fun PrivateKeyInfo.toPrivateKey(): PrivateKey =
          KEY_CONVERTER.getPrivateKey(this)

      /**
       * Convert the [X509CertificateHolder] to a [X509Certificate] using the
       * [CERTIFICATE_CONVERTER].
       */
      private inline fun X509CertificateHolder.toX509Certificate(): X509Certificate =
          CERTIFICATE_CONVERTER.getCertificate(this)
    }
  }
}
