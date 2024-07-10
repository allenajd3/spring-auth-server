package com.ayg.auth.server.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ayg.auth.server.dto.CreateAppuserDTO;
import com.ayg.auth.server.dto.MessageDTO;
import com.ayg.auth.server.entity.AppUser;
import com.ayg.auth.server.entity.Role;
import com.ayg.auth.server.enums.RoleName;
import com.ayg.auth.server.repository.AppUserRepository;
import com.ayg.auth.server.repository.RoleRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {

	private final AppUserRepository appUserRepository;
	private final PasswordEncoder passwordEncoder;
	
	public MessageDTO createUser (CreateAppuserDTO dto) {
		AppUser appUser = AppUser.builder()
				.username(dto.username())
				.password(passwordEncoder.encode(dto.password()))
				.build();
		
//		Set<Role> roles = new HashSet<>();
//		dto.roles().forEach(r->{
//			Role role = roleRepository.findByRole(RoleName.valueOf(r))
//					.orElseThrow(()-> new RuntimeException("role not found"));
//			roles.add(role);
//		});
//		appUser.setRoles(roles);
		appUserRepository.save(appUser);
		return new MessageDTO("user " + appUser.getUsername() + " guardado");
		
		
	}
}
