package com.ayg.auth.server.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ayg.auth.server.entity.AppUser;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser,Integer>{
	
	Optional<AppUser> findByUsername(String username);

}
