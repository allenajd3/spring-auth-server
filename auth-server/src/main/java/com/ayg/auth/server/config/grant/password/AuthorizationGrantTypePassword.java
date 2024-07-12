package com.ayg.auth.server.config.grant.password;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class AuthorizationGrantTypePassword {
    public static final AuthorizationGrantType GRANT_PASSWORD =
        new AuthorizationGrantType("password");
}
