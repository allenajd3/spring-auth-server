package com.ayg.auth.server.dto;

import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateClientDTO {

	private String clientId;
	
	private String clientSecret;
	
	private Set<ClientAuthenticationMethod> authenticationMethods;
	
	private Set<AuthorizationGrantType> grantTypes;
	
	private Set<String> redirectUris;
	
	private Set<String> scopes;
	
	private boolean requireProofKey;
}
