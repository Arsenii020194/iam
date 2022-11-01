package com.example.investments.iam.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisPassword
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate


@Configuration
class RedisConfig {

    @Bean
    fun jedisConnectionFactory(): JedisConnectionFactory {
        return JedisConnectionFactory(RedisStandaloneConfiguration().apply {
            password = RedisPassword.of("eYVX7EwVmmxKPCDmwMtyKVge8oLd2t81")
        })
    }

    @Bean
    fun redisTemplate(): RedisTemplate<String, Any> {
        return RedisTemplate<String, Any>().apply {
            setConnectionFactory(jedisConnectionFactory())
        }
    }
}