package com.ayg.auth.server;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.ayg.auth.server.entity.AppUser;
import com.ayg.auth.server.entity.AppUserRole;
import com.ayg.auth.server.repository.AppUserRepository;
import com.ayg.auth.server.repository.AppUserRoleRepository;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private AppUserRepository userRepository;
    @Autowired
    private AppUserRoleRepository appUserRoleRepository;

    @Override
    public void run(String... args) throws Exception {
        AppUser user = userRepository.findByUsername("admin").orElse(null);
        if (user != null) {
            System.out.println("User: " + user.getUsername());
            user.getUserRoles().forEach(role -> 
                System.out.println("Role: " + role.getRole().getName() + " Client: " + role.getClientId())
            );
        } else {
            System.out.println("User not found");
        }
    }
}
