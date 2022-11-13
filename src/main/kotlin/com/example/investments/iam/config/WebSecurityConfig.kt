package com.example.investments.iam.config

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import java.util.*


@EnableWebSecurity
class WebSecurityConfig {

    @Autowired
    private lateinit var userDetailsService: UserDetailsService

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http.authorizeRequests { authorizeRequests ->
            authorizeRequests.anyRequest().authenticated()
        }
            .authenticationProvider(authenticationProvider())
            .formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun authenticationProvider(): DaoAuthenticationProvider? {
        val authenticationProvider = DaoAuthenticationProvider()
        authenticationProvider.setPasswordEncoder(BCryptPasswordEncoder())
        authenticationProvider.setUserDetailsService(userDetailsService)
        return authenticationProvider
    }
}