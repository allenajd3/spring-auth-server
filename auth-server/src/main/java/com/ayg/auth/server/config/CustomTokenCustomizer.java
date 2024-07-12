package com.ayg.auth.server.config;

import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import com.ayg.auth.server.entity.CustomUserDetails;

@Component 
public class CustomTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (context.getTokenType().getValue().equals("access_token")) {
            CustomUserDetails customUserDetails = (CustomUserDetails) context.getPrincipal().getPrincipal();

            String clientId = context.getAuthorization().getRegisteredClientId();
            var appRoles = customUserDetails.getAppRoles().get(clientId);

            if (appRoles != null) {
                context.getClaims()
                	.claim("roles", appRoles.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                	.claim("username", customUserDetails.getUsername());
                	
            }
        }
    }
}
