package com.agenthun

import io.ktor.network.tls.certificates.generateCertificate
import java.io.File

object CertificateGenerator {
    @JvmStatic
    fun main(args: Array<String>) {
        val jksFile = File("temporary.jks").apply {
            parentFile.mkdirs()
        }
        if (!jksFile.exists()) {
            generateCertificate(jksFile)
        }
    }
}