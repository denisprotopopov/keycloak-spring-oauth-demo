package ru.mvp.spring.oauth.keycloak.controller

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api")
class Controller {

    @GetMapping("/info")
    fun info() = "info page"

    @GetMapping("/secured/info")
    fun secured() = "secured info"
}