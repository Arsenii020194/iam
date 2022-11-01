package com.example.investments.iam.domain.impl

import com.example.investments.iam.domain.api.model.User
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface UserRepository : CrudRepository<User, String>