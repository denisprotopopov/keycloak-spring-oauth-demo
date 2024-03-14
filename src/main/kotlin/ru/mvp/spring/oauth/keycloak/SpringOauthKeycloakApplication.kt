package ru.mvp.spring.oauth.keycloak

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SpringOauthKeycloakApplication {
}

fun main(args: Array<String>) {
    runApplication<SpringOauthKeycloakApplication>(*args)
}