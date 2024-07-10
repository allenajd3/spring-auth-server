package com.ayg.auth.server.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ayg.auth.server.entity.AppUser;
import com.ayg.auth.server.entity.CustomUserDetails;
import com.ayg.auth.server.repository.AppUserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private AppUserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        List<SimpleGrantedAuthority> authorities = user.getUserRoles().stream()
                .map(userRole -> new SimpleGrantedAuthority(userRole.getRole().getName().name()))
                .collect(Collectors.toList());

        return CustomUserDetails.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .userRoles(user.getUserRoles())
                .build();
    }
}