package com.ayg.auth.server.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ayg.auth.server.entity.Role;
import com.ayg.auth.server.enums.RoleName;

@Repository
public interface RoleRepository extends JpaRepository<Role,Integer>{
	
	//Optional<Role> findByRole(RoleName rolName);

}

