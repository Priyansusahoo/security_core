package com.sc.mfa_core.dto;

import com.sc.otp_core.domain.OtpChannel;

/**
 * Immutable domain result of a successfully validated MFA challenge.
 *
 * @param target  The verified recipient identity (e.g. email or phone number)
 * @param channel The delivery channel that was validated
 */
public record MfaVerificationResult(
        String target,
        OtpChannel channel
) {}
