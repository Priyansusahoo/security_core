package com.sc.security_core.auth.dto;

import lombok.*;

@Data
@AllArgsConstructor @NoArgsConstructor @Builder
public class LoginRequest {
	
    private String email;

    @ToString.Exclude
    private String password;
    
}
