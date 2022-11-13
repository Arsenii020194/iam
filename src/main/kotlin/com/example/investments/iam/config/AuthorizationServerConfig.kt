package com.example.investments.iam.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OidcConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientRowMapper
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration
class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(Exception::class)
    fun authServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        customAuthorizationConfiguration(http)
        return http.formLogin(Customizer.withDefaults()).build()
    }

    @Throws(java.lang.Exception::class)
    private fun customAuthorizationConfiguration(http: HttpSecurity) {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer<HttpSecurity>()
        val oidcConfigCustomizer =
            Customizer { customizer: OidcConfigurer ->
                customizer.clientRegistrationEndpoint(
                    Customizer.withDefaults()
                )
            }
        authorizationServerConfigurer.oidc(oidcConfigCustomizer)
        val endpointsMatcher = authorizationServerConfigurer
            .endpointsMatcher
        http
            .requestMatcher(endpointsMatcher)
            .authorizeRequests { authorizeRequests ->
                authorizeRequests.anyRequest().authenticated()
            }
            .oauth2ResourceServer { obj: OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt() }
            .csrf { csrf: CsrfConfigurer<HttpSecurity?> ->
                csrf.ignoringRequestMatchers(
                    endpointsMatcher
                )
            }
            .apply(authorizationServerConfigurer)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun registeredClientRepository(
        jdbcTemplate: JdbcTemplate?,
        objectMapper: ObjectMapper
    ): RegisteredClientRepository? {
        return JdbcRegisteredClientRepository(jdbcTemplate).apply {
            setRegisteredClientRowMapper(RegisteredClientRowMapper().apply {
                setObjectMapper(objectMapper)
            })
        }
    }

    @Bean
    fun oAuth2AuthorizationService(
        registeredClientRepository: RegisteredClientRepository?,
        jdbcTemplate: JdbcTemplate?,
        objectMapper: ObjectMapper
    ): OAuth2AuthorizationService? {
        val rowMapper =
            JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(registeredClientRepository)
        rowMapper.setObjectMapper(objectMapper)
        val authService = JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
        authService.setAuthorizationRowMapper(rowMapper)
        return authService
    }

    @Bean
    fun oAuth2AuthorizationConsentService(
        registeredClientRepository: RegisteredClientRepository?,
        jdbcTemplate: JdbcTemplate?
    ): OAuth2AuthorizationConsentService? {
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext?>? {
        val rsaKey: RSAKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, _: SecurityContext? ->
            jwkSelector.select(
                jwkSet
            )
        }
    }

    @Bean
    fun providerSettings(): ProviderSettings? {
        return ProviderSettings.builder().issuer("http://iam:8080").build()
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder? {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }
}

private fun generateRsa(): RSAKey {
    val keyPair = generateRsaKey()
    val publicKey = keyPair.public as RSAPublicKey
    val privateKey = keyPair.private as RSAPrivateKey
    return RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build()
}

private fun generateRsaKey(): KeyPair {
    val keyPair: KeyPair = try {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        keyPairGenerator.generateKeyPair()
    } catch (ex: java.lang.Exception) {
        throw IllegalStateException(ex)
    }
    return keyPair
}