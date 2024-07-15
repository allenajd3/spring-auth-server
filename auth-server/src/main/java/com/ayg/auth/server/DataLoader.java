package com.ayg.auth.server;

import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.ayg.auth.server.entity.AppUser;
import com.ayg.auth.server.entity.AppUserRole;
import com.ayg.auth.server.entity.Role;
import com.ayg.auth.server.enums.RoleName;
import com.ayg.auth.server.repository.AppUserRepository;
import com.ayg.auth.server.repository.AppUserRoleRepository;
import com.ayg.auth.server.repository.RoleRepository;

@Component
public class DataLoader implements CommandLineRunner {

    @Autowired
    private AppUserRepository userRepository;
    @Autowired
    private AppUserRoleRepository appUserRoleRepository;
    
    @Autowired
    private RoleRepository roleRepository;
    @Override
    public void run(String... args) throws Exception {
    	
    	//ROLE_ADMIN
    	Optional<Role> rolAdmin = roleRepository.findByRole(RoleName.valueOf("ROLE_ADMIN"));
    	if (!rolAdmin.isPresent()) {
    		Role role = Role.builder().name(RoleName.ROLE_ADMIN).build();
    		roleRepository.save(role);
    	}
    	
    	//ROLE_USER
    	Optional<Role> rolUser = roleRepository.findByRole(RoleName.valueOf("ROLE_USER"));
    	if (!rolUser.isPresent()) {
    		Role role = Role.builder().name(RoleName.ROLE_ADMIN).build();
    		roleRepository.save(role);
    	}
    	
//        AppUser user = userRepository.findByUsername("admin").orElse(null);
//        if (user != null) {
//            System.out.println("User: " + user.getUsername());
//            user.getUserRoles().forEach(role -> 
//                System.out.println("Role: " + role.getRole().getName() + " Client: " + role.getClientId())
//            );
//        } else {
//            System.out.println("User not found");
//        }
    }
}
