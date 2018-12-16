package com.agenthun

import com.auth0.jwk.JwkProviderBuilder
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.jwt.jwt
import io.ktor.auth.ldap.ldapAuthenticate
import io.ktor.features.*
import io.ktor.gson.gson
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.jackson.JacksonConverter
import io.ktor.jackson.jackson
import io.ktor.request.*
import io.ktor.response.etag
import io.ktor.response.header
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.sessions.sessions
import io.ktor.util.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import org.slf4j.LoggerFactory
import org.slf4j.event.Level
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.text.DateFormat
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@InternalAPI
@UseExperimental(KtorExperimentalAPI::class)
@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {
    install(CallLogging) {
        level = Level.TRACE
        filter { call -> call.request.path().startsWith("/section1") }
    }
    install(AutoHeadResponse)
    install(CachingHeaders) {
        options { outgoingContent ->
            when (outgoingContent.contentType?.withoutParameters()) {
                ContentType.Text.CSS -> CachingOptions(CacheControl.MaxAge(maxAgeSeconds = 24 * 60 * 60))
                else -> null
            }
        }
    }
    install(CallId) {
        retrieve { call ->
            call.request.header(HttpHeaders.XRequestId)
        }
        val counter = AtomicInteger(0)
        generate { "generated-call-id-${counter.getAndIncrement()}" }
        verify { callId: String ->
            callId.isNotEmpty()
        }
        reply { call: ApplicationCall, callId: String ->
            logger.info("call=$call, callId=$callId")
        }
        retrieveFromHeader(headerName = "testHeaderByRetrieve")
        replyToHeader(headerName = "testHeaderByReply")
        header(headerName = "testHeader")
    }
    install(Compression) {
        gzip {
            priority = 1.0
            condition {
                parameters["e"] == "1"
                request.headers[HttpHeaders.Referrer]?.startsWith("https://my.domin/") == true
            }
        }
        deflate {
            priority = 10.0
            minimumSize(1024)
        }
    }
    install(ConditionalHeaders) {
        version { content -> listOf(EntityTagVersion("tag1")) }
    }
    install(ContentNegotiation) {
        //        register(ContentType.Application.Json, GsonConverter(GsonBuilder().apply {
//
//        }.create()))
        gson {
            setPrettyPrinting()

            disableHtmlEscaping()
            disableInnerClassSerialization()
            enableComplexMapKeySerialization()

            serializeNulls()

            serializeSpecialFloatingPointValues()
            excludeFieldsWithoutExposeAnnotation()

            generateNonExecutableJson()

            setLenient()
        }
        register(ContentType.Application.Json, JacksonConverter(ObjectMapper().apply {

        }))
        jackson {
            enable(SerializationFeature.INDENT_OUTPUT)
            dateFormat = DateFormat.getDateInstance()
            disableDefaultTyping()
        }
    }
    install(CORS) {
        method(HttpMethod.Options)
        header(HttpHeaders.XForwardedProto)
        anyHost()
        host("my-host")
        allowCredentials = true
        maxAge = Duration.ofDays(1)
    }
    install(Authentication) {
        basic(name = "myauth1") {
            realm = "Ktor Server"
            validate { credentials ->
                if (credentials.name == credentials.password) {
                    UserIdPrincipal(credentials.name)
                } else {
                    null
                }
            }
        }
        form(name = "myauth2") {
            userParamName = "user"
            passwordParamName = "password"
            challenge = FormAuthChallenge.Unauthorized
            validate { credentials ->
                if (credentials.name == credentials.password) {
                    UserIdPrincipal(credentials.name)
                } else {
                    null
                }
            }
        }
        basic("name2") {
            skipWhen { call -> call.sessions.get("user_sessions") != null }
        }
        basic("authName") {
            realm = "ktor"
            validate { credentials ->
                UserHashedTableAuth(
                    getDigestFunction("SHA-256", salt = "ktor"), mapOf(
                        "test" to decodeBase64("VltM4nfheqcJSyH887H+4NEOm2tDuKCl83p5axYXlF0=")
                    )
                ).authenticate(credentials)
            }
        }
        basic("authName2") {
            realm = "realm"
            validate { credentials ->
                ldapAuthenticate(credentials, "ldap://localhost:389", "uid=%s, ou=system")
            }
        }
        basic("authName3") {
            realm = "realm"
            validate { credentials ->
                ldapAuthenticate(credentials, "ldap://localhost:389", "cn=%s ou=users") {
                    if (it.name == it.password) {
                        UserIdPrincipal(it.name)
                    } else {
                        null
                    }
                }
            }
        }
    }
    authentication {
        val myRealm = "MyRealm"
        val usersInMyRealmToHA1: Map<String, ByteArray> = mapOf(
            "test" to hex("fb12475e62dedc5c2744d98eb73b8877")
        )
        digest {
            userNameRealmPasswordDigestProvider = { userName, realm ->
                usersInMyRealmToHA1[userName]
            }
        }
    }
    install(Routing) {
        get("/") {
            call.push("/style.css")
            call.respondText(
                """
                <!DOCTYPE html>
                <html>
                    <head>
                        <link rel="stylesheet" type="text/css" href="/style.css">
                    </head>
                    <body>
                        <h1>Hello, World!</h1>
                    </body>
                </html>
            """.trimIndent(), ContentType.Text.Html
            )
            call.application.environment.log.info("hello, call.application.environment.log")
        }
    }
    routing {
        get("/style.css") {
            call.respondText(
                """
                h1 { color: olive }
            """, contentType = ContentType.Text.CSS
            )
        }
    }
    install(ContentNegotiation) {
        gson {
            setDateFormat(DateFormat.LONG)
            setPrettyPrinting()
        }
    }
    install(StatusPages) {
        exception<Throwable> { cause ->
            call.respond(HttpStatusCode.InternalServerError)
        }
    }
    routing {
        get("/health_check") {
            call.respondText("OK")
        }
    }
    routing {
        get("/simple/get") {
            val queryParameters = call.request.queryParameters
            queryParameters.forEach { name, list ->
                logger.info("$name=s, list.size=${list.size}")
                list.forEach {
                    logger.info("$list.item=$it")
                }
            }
            val content = """
              request.call=${call.request.call},
              request.pipeline=${call.request.pipeline},
              request.httpVersion=${call.request.httpVersion},
              request.httpMethod=${call.request.httpMethod},
              request.uri=${call.request.uri},
              request.origin.scheme=${call.request.origin.scheme},
              request.origin.remoteHost=${call.request.origin.remoteHost},
              request.host()=${call.request.host()},
              request.port()=${call.request.port()},
              request.path()=${call.request.path()},
              request.document=${call.request.document()},
            """
            call.respondText(content, ContentType.Text.Html)
        }
    }
    routing {
        post("simple/post/user") {
            val user = call.receive<User>()
            logger.info("user=$user")
            val cookies = call.request.cookies
            cookies.rawCookies.forEach { key, value -> logger.info("cookie: key=$key, value=$value") }
            call.response.header("auth_token", cookies["auth_token"] ?: "")
            call.response.etag("33a64df551425fcc55e4d42a148795d9f25f89d4")

            val multipart = call.receiveMultipart()
            multipart.forEachPart { part ->
                when (part) {
                    is PartData.FormItem -> {
                        if (part.name == "title") {
                            val title = part.value
                            logger.info("title=$title")
                        }
                    }
                    is PartData.FileItem -> {
                        val uploadDir = part.originalFileName
                        val ext = File(part.originalFileName).extension
                        val file = File(
                            uploadDir,
                            "upload.$ext"
                        )
                        part.streamProvider().use { input ->
                            file.outputStream().buffered().use { output -> input.copyToSuspend(output) }
                        }
                    }
                }
                part.dispose
            }
        }
    }
    intercept(ApplicationCallPipeline.Call) {
        if (call.request.uri == "/") {
//            call.respondText("Test String")
        }
    }

    val jwtIssuer = environment.config.property("jwt.domain").getString()
    val jwtAudience = environment.config.property("jwt.audience").getString()
    val jwtRealm = environment.config.property("jwt.realm").getString()

    val jwkIssuer = "https://jwt-provider-domain/"
    val jwkRealm = "ktor jwt auth test"
    val jwkProvider = JwkProviderBuilder(jwkIssuer)
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build()
    authentication {
        jwt {
            realm = jwtRealm
            verifier(jwkProvider, jwkIssuer)
            validate { credentials ->
                if (credentials.payload.audience.contains(jwtAudience)) JWTPrincipal(credentials.payload) else null
            }
        }
    }
//    val exec = Executors.newCachedThreadPool()
//    val selector = ActorSelectorManager(Dispatchers.IO)
//    val socketBuilder = aSocket(selector).tcp()
//    runBlocking {
//        val server = socketBuilder.bind(InetSocketAddress("127.0.0.1", 2323))
//        logger.info("Started echo telnet server at ${server.localAddress}")
//        while (true) {
//            val socket = server.accept()
//            launch {
//                logger.info("Socket accepted: ${socket.remoteAddress}")
//                val input = socket.openReadChannel()
//                val output = socket.openWriteChannel(true)
//                try {
//                    while (true) {
//                        val line = input.readUTF8Line()
//                        logger.info("${socket.remoteAddress}: $line")
//                        output.write("$line\r\n")
//                    }
//                } catch (e: Throwable) {
//                    e.printStackTrace()
//                    socket.close()
//                }
//            }
//        }
//    }
}

data class User(val name: String, val password: String)

val logger = LoggerFactory.getLogger("hun-log")

suspend fun InputStream.copyToSuspend(
    out: OutputStream,
    bufferSize: Int = DEFAULT_BUFFER_SIZE,
    yieldSize: Int = 4 * 1024 * 1024,
    dispatcher: CoroutineDispatcher = Dispatchers.IO
): Long {
    return withContext(dispatcher) {
        val buffer = ByteArray(bufferSize)
        var bytesCopied = 0L
        var bytesAfterYield = 0L
        while (true) {
            val bytes = read(buffer).takeIf { it >= 0 } ?: break
            out.write(buffer, 0, bytes)
            if (bytesAfterYield >= yieldSize) {
                yield()
                bytesAfterYield %= yieldSize
            }
            bytesCopied += bytes
            bytesAfterYield += bytes
        }
        return@withContext bytesCopied
    }
}