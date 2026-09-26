package com.sc.mfa_core.controller;

import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.security_core.auth.AuthService;
import com.sc.security_core.auth.dto.AuthResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST controller exposing endpoints for completing Multi-Factor Authentication.
 */
@RestController
@RequestMapping("/v1/api/auth/mfa")
@RequiredArgsConstructor
@Tag(name = "MFA Controller", description = "Endpoints for Multi-Factor Authentication verification and code resending")
public class MfaController {

    private final AuthService authService;

    @PostMapping("/verify")
    @Operation(summary = "Verify MFA Code", description = "Validates the one-time code against the challenge ticket and issues the JWT token")
    public ResponseEntity<AuthResponse> verify(@Valid @RequestBody MfaVerificationRequest request) {
        AuthResponse response = authService.verifyMfa(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend")
    @Operation(summary = "Resend MFA Code", description = "Dispatches a new verification code for an existing challenge ticket")
    public ResponseEntity<Map<String, String>> resend(@Valid @RequestBody MfaResendRequest request) {
        authService.resendMfa(request);
        return ResponseEntity.ok(Map.of("message", "A new verification code has been dispatched."));
    }
}
