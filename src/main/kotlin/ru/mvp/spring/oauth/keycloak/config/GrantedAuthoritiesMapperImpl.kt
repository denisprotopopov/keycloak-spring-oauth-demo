package ru.mvp.spring.oauth.keycloak.config

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority
import org.springframework.security.oauth2.jwt.JwtClaimNames
import org.springframework.stereotype.Component
import java.net.MalformedURLException
import java.net.URL


//@Component
class GrantedAuthoritiesMapperImpl: GrantedAuthoritiesMapper {
    override fun mapAuthorities(authorities: Collection<GrantedAuthority?>): Collection<GrantedAuthority>? {
        val mappedAuthorities: MutableSet<GrantedAuthority> = HashSet()
        authorities.forEach { authority: GrantedAuthority? ->
            if (OidcUserAuthority::class.java.isInstance(authority)) {
                val oidcUserAuthority = authority as OidcUserAuthority
                val issuer = oidcUserAuthority.idToken.getClaimAsURL(JwtClaimNames.ISS)
                mappedAuthorities.addAll(extractAuthorities(oidcUserAuthority.idToken.claims)!!)
            } else if (OAuth2UserAuthority::class.java.isInstance(authority)) {
                try {
                    val oauth2UserAuthority = authority as OAuth2UserAuthority
                    val userAttributes =
                        oauth2UserAuthority.attributes
                    val issuer = URL(userAttributes[JwtClaimNames.ISS].toString())
                    mappedAuthorities.addAll(extractAuthorities(userAttributes)!!)
                } catch (e: MalformedURLException) {
                    throw RuntimeException(e)
                }
            }
        }
        return mappedAuthorities
    };

    private fun extractAuthorities(claims: Map<String, Any>): Collection<GrantedAuthority>? {
        return listOf(OAuth2UserAuthority("ADMINREALM",mapOf("ROLE" to "ADMINREALM")) )
    }
}