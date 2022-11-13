package com.example.investments.iam.config

import com.example.investments.iam.domain.api.model.User
import com.example.investments.iam.domain.api.model.UserMixin
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.jackson2.CoreJackson2Module
import org.springframework.security.jackson2.SecurityJackson2Modules
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module

@Configuration
class ObjectMapperConfig {

    @Bean
    fun objectMapper(): ObjectMapper = jacksonObjectMapper()
        .addMixIn(User::class.java, UserMixin::class.java)
        .registerModules(
            CoreJackson2Module(),
            OAuth2AuthorizationServerJackson2Module()
        )
        .registerModules(SecurityJackson2Modules.getModules(JdbcOAuth2AuthorizationService::class.java.classLoader))
}