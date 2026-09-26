package com.sc.security_core.auth.dto;

import lombok.*;

@Data
@AllArgsConstructor @NoArgsConstructor @Builder
public non-sealed class AuthResponse implements LoginResponse {

    @ToString.Exclude
    private String token;
    
    private String message;
    
}
