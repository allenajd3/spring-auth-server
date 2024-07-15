package com.ajd.springboot.client.controllers;

import java.util.Collections;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthorizationController {
	
	@GetMapping("/authorized")
	public Map<String, String> authorized(@RequestParam String code) {
		return Collections.singletonMap("code", code);
	}
}
