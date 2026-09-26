package com.sc.mfa_core.dto;

import com.sc.otp_core.domain.OtpChannel;
import lombok.Builder;

/**
 * Data Transfer Object returned to the client when a secondary authentication factor is required.
 *
 * @param mfaRequired       Flag indicating that MFA completion is mandatory to obtain an access token
 * @param challengeToken    The ephemeral token required to submit or resend the verification code
 * @param channel           The channel utilized to dispatch the code (e.g. EMAIL, SMS)
 * @param maskedDestination Obfuscated target identifier suitable for UI display (e.g. "a***n@modelx.store")
 * @param message           User-facing informational message
 */
@Builder
public record MfaChallengeResponse(
        boolean mfaRequired,
        String challengeToken,
        OtpChannel channel,
        String maskedDestination,
        String message
) {
}
