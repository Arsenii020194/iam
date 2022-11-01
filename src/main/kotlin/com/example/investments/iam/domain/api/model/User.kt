package com.example.investments.iam.domain.api.model

import org.springframework.data.annotation.Id
import org.springframework.data.redis.core.RedisHash
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@RedisHash("User")
class User(
    @Id
    private val username: String,
    private val password: String,
    private val authorities: MutableCollection<out GrantedAuthority>
) : UserDetails {
    override fun getPassword(): String = password
    override fun getUsername(): String = username
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = authorities
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = true
}