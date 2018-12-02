package com.agenthun

import io.ktor.application.*
import io.ktor.features.CallLogging
import io.ktor.features.ContentNegotiation
import io.ktor.features.StatusPages
import io.ktor.features.origin
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.push
import io.ktor.network.selector.ActorSelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
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
import io.ktor.util.cio.write
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.io.readUTF8Line
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.text.DateFormat
import java.util.concurrent.Executors

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