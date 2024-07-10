package com.ayg.auth.server.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.StringUtils;

import com.ayg.auth.server.entity.AppUser;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration(proxyBeanMethods = false)
public class TokenConfiguration {

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}


	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString())
				.build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex.getMessage());
		}
		return keyPair;
	}

//	/*
//	 * Customización de los token
//	 * */
//	@Bean
//	public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
//		return context -> {
//			Authentication principal = context.getPrincipal();
//			if(context.getTokenType().getValue().equals("id_token")) {
//				context.getClaims().claim("token_type", "id token");
//				
//			}
//			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//				context.getClaims().claim("token_type", "access token");
//				Set<String> roles = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
//				context.getClaims()
//						.claim("roles", roles)
//						.claim("username", principal.getName());
//			}
//			
//			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//	            AppUser customUserDetails = (AppUser) context.getPrincipal().getPrincipal();
//
//	            String clientId = context.getAuthorizationGrant().get
//	            var appRoles = customUserDetails.getAppRoles().get(clientId);
//
//	            if (appRoles != null) {
//	                context.getClaims().claim("roles", appRoles.stream()
//	                        .map(GrantedAuthority::getAuthority)
//	                        .collect(Collectors.toList()));
//	            }
//	        }
//		};
//	}
}