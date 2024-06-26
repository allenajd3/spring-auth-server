package com.ayg.auth.server.dto;

import java.util.List;

public record CreateAppuserDTO (

	String username,
	String password,
	List<String> roles) {
	
}
