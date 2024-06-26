package com.ayg.auth.server.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ayg.auth.server.dto.CreateAppuserDTO;
import com.ayg.auth.server.dto.MessageDTO;
import com.ayg.auth.server.service.AppUserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping ("/auth")
public class AuthController {
	
	private final AppUserService appUserService;
	
	@PostMapping("/create")
	public ResponseEntity<MessageDTO> createUser (@RequestBody CreateAppuserDTO dto){
		return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.createUser(dto));
	}
}
