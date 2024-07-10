package com.ayg.auth.server.entity;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import lombok.Builder;
import lombok.Getter;

public class CustomUserDetails extends User {
    private final Map<String, Collection<GrantedAuthority>> appRoles;

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities,
                             Set<AppUserRole> userRoles) {
        super(username, password, authorities);
        
        this.appRoles = userRoles.stream()
                .collect(Collectors.groupingBy(
                        AppUserRole::getClientId,
                        Collectors.mapping(ur -> new SimpleGrantedAuthority(ur.getRole().getName().name()), Collectors.toSet())
                ));
    }

    public Map<String, Collection<GrantedAuthority>> getAppRoles() {
        return appRoles;
    }