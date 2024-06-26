package com.ajd.springboot.client.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ajd.springboot.client.dto.MessageDTO;


@RestController
@RequestMapping("/resource")
public class AppController {

	@GetMapping("/user")
	public ResponseEntity<MessageDTO> helloUser(Authentication auth){
		return ResponseEntity.ok(new MessageDTO("Hello " + auth.getName()));
	}
	
	@GetMapping("/admin")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<MessageDTO> helloAdmin(Authentication auth){
		return ResponseEntity.ok(new MessageDTO("Hello MR. " + auth.getName()));
	}
	
}
