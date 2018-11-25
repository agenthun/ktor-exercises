package com.agenthun

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.Routing
import io.ktor.routing.get
import io.ktor.routing.routing

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
@kotlin.jvm.JvmOverloads
fun Application.module(testing: Boolean = false) {
    install(Routing) {
        get("/") {
            call.respondText("hello, agenthun~", ContentType.Text.Html)
        }
    }
    routing {
        get("/simple") {
            call.respondText("hello, simple", ContentType.Text.Html)
        }
    }
}
