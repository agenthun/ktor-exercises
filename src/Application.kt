package com.agenthun

import io.ktor.application.Application
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.features.origin
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.PartData
import io.ktor.http.content.forEachPart
import io.ktor.http.content.streamProvider
import io.ktor.http.push
import io.ktor.request.*
import io.ktor.response.etag
import io.ktor.response.header
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import org.slf4j.LoggerFactory
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.text.DateFormat

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@UseExperimental(KtorExperimentalAPI::class)
@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {
    install(CallLogging)
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