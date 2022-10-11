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
import io.netty.channel.ChannelHandler
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
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpRequest
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.codec.http.HttpVersion
import io.netty.handler.codec.http.TooLongHttpContentException
import io.netty.handler.codec.http.TooLongHttpHeaderException
import io.netty.handler.codec.http.TooLongHttpLineException
import io.netty.handler.logging.LoggingHandler
import io.netty.handler.ssl.SslContextBuilder
import io.netty.util.ReferenceCountUtil
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import java.io.Closeable
import java.math.BigInteger
import java.net.URL
import java.nio.file.Path
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.Year
import java.time.ZoneId
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.Date
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.io.path.bufferedReader
import kotlin.math.max
import kotlin.properties.Delegates.notNull
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
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
 * [Server] is an intercepting proxy which enables received [Request] and [Response] data to be
 * transformed dynamically.
 *
 * @property handler the [ChannelHandler] which handles request/response proxying and interception
 */
class Server private constructor(private val handler: ChannelHandler) : Closeable {

  companion object {

    /**
     * Create a proxy [Server] instance.
     *
     * For the proxy [Server] to support *HTTPS CONNECT* requests, the [certificatePath] and
     * [privateKeyPath] must be provided. This enables the server to decrypt the proxied requests
     * and responses for interception, assuming the client appropriately trusts the certificate at
     * the given [certificatePath].
     *
     * @param interceptors the [Array] of [Interceptor] to use to intercept proxy requests and
     * responses. The first [Interceptor.interceptable] interceptor is used for each proxy request
     * @param proxier the [Proxier] to use to execute proxy requests
     * @param executor the [Executor] to use to asynchronously intercept requests and responses
     * @param certificatePath the [Path] to the X.509 *trusted certificate*
     * @param privateKeyPath the [Path] to the PKCS8 private key for the *trusted certificate*
     * @param credentials the [Credentials] required in the [HttpHeaderNames.PROXY_AUTHORIZATION]
     * @return the proxy [Server]
     * @throws RuntimeException if the proxy server failed to initialize
     */
    @JvmStatic
    @JvmOverloads
    fun create(
        vararg interceptors: Interceptor,
        proxier: Proxier? = null,
        executor: Executor? = null,
        certificatePath: Path? = null,
        privateKeyPath: Path? = null,
        credentials: Credentials? = null
    ): Server {
      fun Path.parse(): Any =
          PEMParser(bufferedReader(Charsets.US_ASCII)).use(PEMParser::readObject)
      val certificate =
          certificatePath?.parse()?.let {
            when (it) {
              is X509CertificateHolder -> it
              else -> error("Failed to parse certificate")
            }
          }
      val privateKey =
          privateKeyPath?.parse()?.let {
            when (it) {
              is PrivateKeyInfo -> it
              is PEMKeyPair -> it.privateKeyInfo
              else -> error("Failed to parse private key")
            }
          }
      return Server(
          Handler(
              interceptors.toList(),
              proxier ?: Proxier.create(),
              executor
                  ?: Executors.newFixedThreadPool(
                      max(Runtime.getRuntime().availableProcessors(), 64)),
              certificate,
              privateKey,
              credentials))
    }

    init {
      InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
    }

    /** The [Logger] for the [Server]. */
    private val LOGGER: Logger = LoggerFactory.getLogger(Server::class.java)

    /** Get a [HttpServerCodec] instance. */
    private val HTTP_SERVER_CODEC: HttpServerCodec
      get() = HttpServerCodec()

    /** Get a [HttpObjectAggregator] instance. */
    private val HTTP_OBJECT_AGGREGATOR: HttpObjectAggregator
      get() = HttpObjectAggregator(/* 8 MiB */ 8 * 1024 * 1024)
  }

  private val started = AtomicBoolean()
  private val stopped = AtomicBoolean()

  private val acceptorGroup by lazy<EventLoopGroup> { NioEventLoopGroup() }
  private val workerGroup by lazy<EventLoopGroup> { NioEventLoopGroup() }
  private var channel by notNull<Channel>()

  /**
   * Synchronously start the proxy server on the [port].
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
            .handler(LoggingHandler())
            .childHandler(Initializer())
            .bind(port)
            .syncUninterruptibly()
            .run { if (isSuccess) channel() else throw cause() }
  }

  /**
   * Synchronously stop the proxy server.
   *
   * @throws Exception if the proxy server failed to stop
   * @return `this` stopped [Server] instance
   */
  @Throws(Exception::class)
  fun stop(): Server = apply {
    check(started.get()) { "The proxy server is not running" }
    check(stopped.compareAndSet(false, true)) { "The proxy server was already stopped" }
    LOGGER.info("Stopping proxy server")
    channel.close().syncUninterruptibly().apply { if (!isSuccess) throw cause() }
    fun EventLoopGroup.close() =
        takeUnless { it.isShuttingDown || it.isShutdown || it.isTerminated }?.shutdownGracefully()
    acceptorGroup.close()
    workerGroup.close()
  }

  /**
   * Synchronously [stop] the proxy server.
   *
   * @see stop for details about stopping the proxy server
   */
  override fun close() {
    stop()
  }

  /**
   * [Initializer] initializes the [Channel] with the [HttpServerCodec], [HttpObjectAggregator], and
   * [handler]
   */
  inner class Initializer : ChannelInitializer<Channel>() {

    override fun initChannel(ch: Channel) {
      ch.pipeline().addFirst(HTTP_SERVER_CODEC, HTTP_OBJECT_AGGREGATOR, handler)
    }
  }

  /** [Handler] handles received proxy requests. */
  private class Handler(
      private val interceptors: List<Interceptor>,
      private val proxier: Proxier,
      private val executor: Executor,
      private val certificate: X509CertificateHolder?,
      private val privateKey: PrivateKeyInfo?,
      private val credentials: Credentials?
  ) : ChannelInboundHandlerAdapter() {

    /** The [host] and [port] of the proxy request [Destination]. */
    private data class Destination(val host: String, val port: Int)
    private var destination: Destination? = null

    /**
     * The [LoadingCache] that stores a generated [X509Certificate] for *secure* proxy connection to
     * a host.
     */
    private val certificates by
        lazy<LoadingCache<String, X509Certificate>> {
          Caffeine.newBuilder().maximumSize(64).build(::generateCertificate)
        }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
      LOGGER.debug("Reading message {}", msg)
      when (msg) {
        is HttpRequest ->
            msg.takeIf { it.decoded(ctx) }
                ?.runCatching {
                  if (method() == HttpMethod.CONNECT) handleConnect(ctx) else handleProxy(ctx)
                }
                ?.onFailure {
                  LOGGER.error("Failed to proxy HTTP(S) request", it)
                  ctx.channel().close()
                }
        is ByteBuf ->
            msg.runCatching { handleTLSHandshake(ctx) }
                .onFailure {
                  LOGGER.error("Failed to initialize TLS connection", it)
                  ctx.channel().close()
                }
      }
    }

    /**
     * Check the if [HttpRequest] failed to be decoded. If so, stop processing the request and
     * respond with relevant error code.
     */
    private fun HttpRequest.decoded(ctx: ChannelHandlerContext): Boolean =
        decoderResult()
            .takeIf { it.isFailure }
            ?.cause()
            ?.takeIf { it is DecoderException }
            ?.also {
              LOGGER.error("Failed to decode HTTP request", it)
              ctx.writeStatus(
                  when (it) {
                    is TooLongHttpLineException -> HttpResponseStatus.REQUEST_URI_TOO_LONG
                    is TooLongHttpHeaderException ->
                        HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
                    is TooLongHttpContentException -> HttpResponseStatus.REQUEST_ENTITY_TOO_LARGE
                    else -> HttpResponseStatus.BAD_REQUEST
                  })
              ReferenceCountUtil.release(this)
            } == null

    /** Handle the initial [HttpMethod.CONNECT] request. */
    private fun HttpRequest.handleConnect(ctx: ChannelHandlerContext) {
      check(certificate != null && privateKey != null) {
        "Certificate and private key required for HTTPS"
      }
      val (host, port) =
          checkNotNull(uri().split(':', limit = 2).takeIf { it.size == 2 }) {
            "Unexpected URI ${uri()}"
          }
      destination = Destination(host, checkNotNull(port.toIntOrNull()) { "Invalid port $port" })
      ctx.writeStatus(HttpResponseStatus.OK)
      ctx.channel().pipeline().remove(HttpServerCodec::class.java)
      ctx.channel().pipeline().remove(HttpObjectAggregator::class.java)
      ReferenceCountUtil.release(this)
    }

    /** Handle the proxying of the [FullHttpRequest]. */
    private fun HttpRequest.handleProxy(ctx: ChannelHandlerContext) {
      check(this is FullHttpRequest) { "Unexpected HTTP request" }
      if (!isAuthorized()) {
        ctx.writeStatus(HttpResponseStatus.UNAUTHORIZED)
        ReferenceCountUtil.release(this)
        return
      }
      val request =
          Request(
              URL(destination?.run { "https://$host:$port${uri()}" } ?: uri()),
              method().name(),
              headers().associate { (key, value) -> key to value },
              ByteBufUtil.getBytes(content()))
      executor.execute proxy@{
        val interceptor = interceptors.find { it.interceptable(request) } ?: object : Interceptor {}
        request
            .runCatching { also(interceptor::intercept) }
            .onFailure {
              LOGGER.error("Failed to intercept request", it)
              ctx.writeStatus(HttpResponseStatus.INTERNAL_SERVER_ERROR)
              return@proxy
            }
            .mapCatching(proxier::execute)
            .onFailure {
              LOGGER.error("Failed to execute proxy request", it)
              ctx.writeStatus(HttpResponseStatus.BAD_GATEWAY)
              return@proxy
            }
            .mapCatching { it.also(interceptor::intercept) }
            .onFailure {
              LOGGER.error("Failed to intercept response", it)
              ctx.writeStatus(HttpResponseStatus.INTERNAL_SERVER_ERROR)
              return@proxy
            }
            .onSuccess {
              ctx.writeAndFlush(
                  DefaultFullHttpResponse(
                      HttpVersion.HTTP_1_1,
                      HttpResponseStatus.valueOf(it.statusCode),
                      it.body?.let(Unpooled::copiedBuffer) ?: Unpooled.EMPTY_BUFFER,
                      DefaultHttpHeaders().apply {
                        it.headers.forEach(::add)
                        it.body?.apply { set(HttpHeaderNames.CONTENT_LENGTH, size) }
                      },
                      EmptyHttpHeaders.INSTANCE))
            }
      }
      ReferenceCountUtil.release(this)
    }

    /**
     * Check if the [HttpRequest] contains the [HttpHeaderNames.PROXY_AUTHORIZATION] header matching
     * the [credentials].
     */
    private fun HttpRequest.isAuthorized(): Boolean =
        credentials == null ||
            credentials ==
                headers()[HttpHeaderNames.PROXY_AUTHORIZATION]
                    ?.takeIf { it.startsWith("Basic ") }
                    ?.removePrefix("Basic ")
                    ?.let { Base64.getDecoder().decode(it).decodeToString() }
                    ?.split(':', limit = 2)
                    ?.let { (username, password) -> Credentials(username, password) }

    /** Handle the received [ByteBuf]. */
    private fun ByteBuf.handleTLSHandshake(ctx: ChannelHandlerContext) {
      check(getByte(0) == TLS_HANDSHAKE) { "Unexpected data" }
      val certificate = certificates[checkNotNull(destination?.host) { "Unknown destination" }]
      val sslContext =
          SslContextBuilder.forServer(PEM_CONVERTER.getPrivateKey(privateKey), certificate).build()
      ctx.pipeline()
          .addFirst(sslContext.newHandler(ctx.alloc()), HTTP_SERVER_CODEC, HTTP_OBJECT_AGGREGATOR)
      ctx.pipeline().fireChannelRead(this)
    }

    /**
     * Generate a [X509Certificate] for the proxy request with the [certificate], [privateKey], and
     * [host].
     */
    private fun generateCertificate(host: String): X509Certificate {
      val publicKey = PEM_CONVERTER.getPublicKey(certificate?.subjectPublicKeyInfo)
      val privateKey = PEM_CONVERTER.getPrivateKey(privateKey)
      val certificateBuilder =
          JcaX509v3CertificateBuilder(
                  certificate?.subject,
                  BigInteger(64, SecureRandom()),
                  Date.from(Instant.now().atZone(ZoneId.systemDefault()).minusDays(1).toInstant()),
                  Date.from(
                      Year.now()
                          .plus(3, ChronoUnit.YEARS)
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
      val signer = JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey)
      val certificateConverter = JcaX509CertificateConverter().setProvider(BOUNCY_CASTLE_PROVIDER)
      return certificateConverter.getCertificate(certificateBuilder.build(signer))
    }

    private companion object {

      /** [TLS_HANDSHAKE] is the first [Byte] of the initial TLS handshake message. */
      const val TLS_HANDSHAKE: Byte = 22

      /** The [BouncyCastleProvider] to use to generate certificates. */
      private val BOUNCY_CASTLE_PROVIDER by
          lazy<Provider> { BouncyCastleProvider().also { Security.addProvider(it) } }

      /** The [JcaPEMKeyConverter] to use to extract keys from certificates. */
      private val PEM_CONVERTER by
          lazy<JcaPEMKeyConverter> { JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE_PROVIDER) }

      /** Write and flush an HTTP response with the [status] using the [ChannelHandlerContext]. */
      fun ChannelHandlerContext.writeStatus(status: HttpResponseStatus) {
        writeAndFlush(DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status))
      }
    }
  }
}
