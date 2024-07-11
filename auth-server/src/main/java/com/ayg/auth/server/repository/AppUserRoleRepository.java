package com.ayg.auth.server.repository;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ayg.auth.server.entity.AppUserRole;

@Repository
public interface AppUserRoleRepository extends JpaRepository<AppUserRole,Integer>{
	
	Optional<AppUserRole> findById(Integer id);
	Optional<AppUserRole> findByClientId(String clientId);
	Optional<Set<AppUserRole>> findByUserId(Long userId);

}
