package com.ggomg.teamsauth.security

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.awt.PageAttributes.MediaType
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*

@Configuration
@EnableWebSecurity
class SecurityConfig2 {

    @Bean
    fun authorizationServerSecurityFilterChain(
        http: HttpSecurity,
    ): SecurityFilterChain {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

        http
            .getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc(Customizer.withDefaults())

        http.exceptionHandling { exceptions ->
            exceptions.defaultAuthenticationEntryPointFor(
                LoginUrlAuthenticationEntryPoint("/login"),
                MediaTypeRequestMatcher(org.springframework.http.MediaType.TEXT_HTML)
            )
        }

        return http.build()
    }
    
    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests { authorize ->
                authorize.anyRequest().authenticated()
            }.formLogin(Customizer.withDefaults())
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService {
        val userDetails = User.withUsername("user").password("password").roles("USER").build()
        return InMemoryUserDetailsManager(userDetails)
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("wjh-client")
            .clientSecret("wjh-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
            .postLogoutRedirectUri("http://127.0.0.1:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build()
        return InMemoryRegisteredClientRepository(oidcClient)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    private fun generateRsaKey(): KeyPair =
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)


    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().build()


}