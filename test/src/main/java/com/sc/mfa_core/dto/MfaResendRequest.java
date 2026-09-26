package com.sc.mfa_core.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Data Transfer Object submitted by the client to request a fresh verification code
 * for an active MFA challenge.
 *
 * @param challengeToken The active challenge identifier
 */
public record MfaResendRequest(

        @NotBlank(message = "Challenge token cannot be blank")
        String challengeToken
) {
}