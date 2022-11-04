package com.example.investments.iam.domain.api.model

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.JsonDeserializer
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.MissingNode
import org.springframework.security.core.GrantedAuthority
import java.io.IOException

class UserDeserializer : JsonDeserializer<User>() {
    @Throws(IOException::class)
    override fun deserialize(
        jsonParser: JsonParser,
        deserializationContext: DeserializationContext?
    ): User {
        val mapper: ObjectMapper = jsonParser.getCodec() as ObjectMapper
        val jsonNode: JsonNode = mapper.readTree(jsonParser)
        val username = readJsonNode(jsonNode, "username").asText()
        val password: String = readJsonNode(jsonNode, "password").asText()
        val authorities: Collection<GrantedAuthority> =
            mapper.readerFor(object : TypeReference<Collection<GrantedAuthority>>() {})
                .readValue(jsonNode.get("authorities"))
        return User(username, password, authorities.toMutableList())
    }

    private fun readJsonNode(jsonNode: JsonNode, field: String): JsonNode {
        return if (jsonNode.has(field)) jsonNode.get(field) else MissingNode.getInstance()
    }
}