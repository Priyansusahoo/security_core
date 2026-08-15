package com.sc.security_core.auth.dto;

import com.sc.security_core.user.Role;
import lombok.*;

@Data
@AllArgsConstructor @NoArgsConstructor @Builder
public class RegisterRequest {
	
    private String firstName;
    
    private String lastName;
    
    private String email;

    @ToString.Exclude
    private String password;
    
    private Role role;

}
