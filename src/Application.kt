package com.agenthun

import io.ktor.application.Application
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.features.ContentNegotiation
import io.ktor.features.origin
import io.ktor.gson.gson
import io.ktor.http.ContentType
import io.ktor.request.*
import io.ktor.response.etag
import io.ktor.response.header
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.post
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import org.slf4j.LoggerFactory
import java.text.DateFormat

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@UseExperimental(KtorExperimentalAPI::class)
@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {
    install(Routing) {
        get("/") {
            //            call.respondText("hello, agenthun~", ContentType.Text.Html)
            val uri = call.request.uri
            call.respondText("Request uri:$uri")
        }
    }
    install(ContentNegotiation) {
        gson {
            setDateFormat(DateFormat.LONG)
            setPrettyPrinting()
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
}

data class User(val name: String, val password: String)

val logger = LoggerFactory.getLogger("hun-log")