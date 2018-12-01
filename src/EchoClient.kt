package com.agenthun

import io.ktor.network.selector.ActorSelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.util.KtorExperimentalAPI
import io.ktor.util.cio.write
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.io.readUTF8Line
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress

@UseExperimental(KtorExperimentalAPI::class)
fun main(args: Array<String>) {
    runBlocking {
        val socket = aSocket(ActorSelectorManager(Dispatchers.IO)).tcp().connect(InetSocketAddress("127.0.0.1", 2323))
        val input = socket.openReadChannel()
        val output = socket.openWriteChannel(true)

        output.write("hello\r\n")
        val response = input.readUTF8Line()
        println("Server said: $response")
        socket.close()

        val w = socket.openWriteChannel()
        w.write("GET / HTTP/1.1\r\n")
        w.write("Host: baidu.com\r\n")
        w.write("\r\n")
        w.flush()
        val r = socket.openReadChannel()
        println(r.readUTF8Line())
    }
}