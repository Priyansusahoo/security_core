package com.sc.security_core.auth;

import com.sc.security_core.auth.dto.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/v1/api/auth/")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
    	
        return ResponseEntity.ok(authService.register(request));
        
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
    	
        return ResponseEntity.ok(authService.login(request));
        
    }

    @PostMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@Valid @RequestBody EmailVerificationRequest request) {
        return ResponseEntity.ok(authService.verifyEmail(request));
    }

    @PostMapping("/verify-email/resend")
    public ResponseEntity<Map<String, String>> resendEmailVerification(@Valid @RequestBody EmailResendRequest request) {
        authService.resendEmailVerification(request);
        return ResponseEntity.ok(Map.of("message", "A new verification code has been dispatched."));
    }
}
