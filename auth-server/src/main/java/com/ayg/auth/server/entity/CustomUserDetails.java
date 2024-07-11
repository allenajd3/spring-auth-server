package com.ayg.auth.server.entity;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class CustomUserDetails extends User {
    private final Map<String, Collection<GrantedAuthority>> appRoles = new HashMap<>();

    public CustomUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities,
                             List<AppUserRole> list) {
        super(username, password, authorities);
        list.stream().forEach(ur -> {
        	appRoles.put(ur.getClientId(),Arrays.asList(new SimpleGrantedAuthority(ur.getRole().getName().name())));
        });
    }    		
    public static CustomUserDetails build(String username, String password, Collection<? extends GrantedAuthority> authorities,
                                          List<AppUserRole> list) {
        return new CustomUserDetails(username, password, authorities, list);
    }

    public Map<String, Collection<GrantedAuthority>> getAppRoles() {
        return appRoles;
    }
}