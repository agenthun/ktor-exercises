package com.agenthun

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.features.websocket.ws
import io.ktor.http.HttpMethod
import io.ktor.http.cio.websocket.Frame
import io.ktor.http.cio.websocket.readText
import io.ktor.websocket.WebSockets
import kotlinx.coroutines.ObsoleteCoroutinesApi
import kotlinx.coroutines.channels.filterNotNull
import kotlinx.coroutines.channels.map

@UseExperimental(ObsoleteCoroutinesApi::class)
suspend fun main(args: Array<String>) {
    val client = HttpClient(CIO).config { install(WebSockets) }
    client.ws(method = HttpMethod.Get, host = "127.0.0.1", port = 8080, path = "/route/path/to/ws") {
        send(Frame.Text("Hello World"))
        for (message in incoming.map { it as? Frame.Text }.filterNotNull()) {
            println(message.readText())
        }
    }
}