package com.sc.security_core.auth.dto;

import lombok.*;

@Data
@AllArgsConstructor @NoArgsConstructor @Builder
public class AuthResponse {

    @ToString.Exclude
    private String token;
    
    private String message;
    
}
