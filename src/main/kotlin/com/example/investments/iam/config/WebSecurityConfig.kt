package com.example.investments.iam.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@Configuration
class WebSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(
        java.lang.Exception::class
    )
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(
            OAuth2AuthorizationServerConfigurer::class.java
                    as Class<OAuth2AuthorizationServerConfigurer<HttpSecurity>>
        ).oidc(Customizer.withDefaults())

        http
            .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
                exceptions.authenticationEntryPoint(
                    LoginUrlAuthenticationEntryPoint("/login")
                )
            }
            .oauth2ResourceServer { obj: OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt() }
        return http.build()
    }

    @Bean
    @Throws(Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http
            .authorizeHttpRequests { authorize ->
                authorize
                    .anyRequest().permitAll()
            }.formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository? {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("messaging-client")
            .clientSecret("\$2a\$10\$o0AL.mqVbfIMptKu3T0UOOoOJQeWkjhLHXIJE11dGq188.xqr8MlO")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
            .redirectUri("http://127.0.0.1:8090/login/oauth2/code/messaging-client-oidc")
            .redirectUri("http://127.0.0.1:8090/authorized")
            .scope(OidcScopes.OPENID)
            .scope("message.read")
            .scope("message.write")
            .scope("clients.create")
            .scope("clients.read")
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationService? {
        return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate?,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationConsentService? {
        return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext?>? {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.getPublic() as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.getPrivate() as RSAPrivateKey
        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet<SecurityContext?>(jwkSet)
    }

    private fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair
        keyPair = try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder? {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun providerSettings(): ProviderSettings? {
        return ProviderSettings.builder().build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun embeddedDatabase(): EmbeddedDatabase? {
        return EmbeddedDatabaseBuilder()
            .generateUniqueName(true)
            .setType(EmbeddedDatabaseType.H2)
            .setScriptEncoding("UTF-8")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
            .build()
    }

}