package com.ayg.auth.server.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ayg.auth.server.dto.CreateClientDTO;
import com.ayg.auth.server.dto.MessageDTO;
import com.ayg.auth.server.service.ClientService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequiredArgsConstructor
@RequestMapping ("/client")
@Slf4j
public class ClientController {
	
	private final ClientService clientService;
	
	@PostMapping("/create")
	public ResponseEntity<MessageDTO> createUser (@RequestBody CreateClientDTO dto){
		return ResponseEntity.status(HttpStatus.CREATED).body(clientService.create(dto));
	}
}