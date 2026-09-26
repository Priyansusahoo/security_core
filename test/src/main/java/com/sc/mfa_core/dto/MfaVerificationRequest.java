package com.sc.mfa_core.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object submitted by the client to verify an MFA challenge code.
 *
 * @param challengeToken The challenge identifier provided during the login challenge response
 * @param code           The candidate one-time verification code entered by the user
 */
public record MfaVerificationRequest(

        @NotBlank(message = "Challenge token cannot be blank")
        String challengeToken,

        @NotBlank(message = "Verification code cannot be blank")
        String code
) {
}