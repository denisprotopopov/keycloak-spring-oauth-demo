package ru.mvp.spring.oauth.keycloak.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {

    @Bean
    @Throws(Exception::class)
    fun clientSecurityFilterChain(
        http: HttpSecurity,
        clientRegistrationRepository: InMemoryClientRegistrationRepository?
    ): SecurityFilterChain? {
        http.oauth2Login(withDefaults())
        http.logout { logout: LogoutConfigurer<HttpSecurity?> ->
            logout.logoutSuccessHandler(
                OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository)
            )
        }
        // @formatter:off
        http.authorizeHttpRequests{ex -> ex
            .requestMatchers("/api/info", "/login/**", "/oauth2/**").permitAll()
            .requestMatchers("/api/secured/info").hasAuthority("ADMINREALM")
            .anyRequest().authenticated()

        }.oauth2ResourceServer { resourceServerConfigurer -> resourceServerConfigurer
        .jwt {jwtConfigurer -> jwtConfigurer
        .jwtAuthenticationConverter(jwtAuthenticationConverter())
        }
        }
        // @formatter:on
        return http.build()
    }

    @Bean
    @Throws(java.lang.Exception::class)
    fun authenticationManager(http: HttpSecurity): AuthenticationManager? {
        return http.getSharedObject(AuthenticationManagerBuilder::class.java)
            .build()
    }

    @Bean
    fun jwtAuthenticationConverter(): Converter<Jwt?, AbstractAuthenticationToken?>? {
        val jwtAuthenticationConverter = JwtAuthenticationConverter()
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter())
        return jwtAuthenticationConverter
    }

    @Bean
    fun jwtGrantedAuthoritiesConverter(): Converter<Jwt, Collection<GrantedAuthority>> =
        object: Converter<Jwt, Collection<GrantedAuthority>> {
            override fun convert(source: Jwt): Collection<GrantedAuthority>? {
                val grantedAuthorities = JwtGrantedAuthoritiesConverter().convert(source)
                val realmAccess: Map<String,Any> = source.claims["realm_access"] as Map<String,Any>
                if (realmAccess["roles"] == null) {
                    return grantedAuthorities
                }
                val roles = realmAccess["roles"] as List<String>?
                val keycloakAuthorities = roles!!.map { role: Any? ->
                    SimpleGrantedAuthority(
                        "$role"
                    )
                }.toList()
                grantedAuthorities.addAll(keycloakAuthorities)
                return grantedAuthorities
            }
        }

}