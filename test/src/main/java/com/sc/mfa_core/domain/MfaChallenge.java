package com.sc.mfa_core.domain;

import com.sc.otp_core.domain.OtpChannel;
import lombok.Builder;

import java.io.Serializable;
import java.time.Instant;

/**
 * Immutable domain representation of an active Multi-Factor Authentication challenge.
 * <p>
 * Created upon successful primary credential verification (password), holding the ephemeral
 * state required to complete the secondary authentication factor.
 * </p>
 *
 * @param challengeToken Opaque, high-entropy ticket provided to the client
 * @param target         The recipient identity (e.g. user email or phone number)
 * @param channel        The channel through which the challenge was dispatched
 * @param createdAt      Timestamp when the challenge was initiated
 * @param expiresAt      Timestamp when this challenge becomes invalid
 */
@Builder(toBuilder = true)
public record MfaChallenge(
        String challengeToken,
        String target,
        OtpChannel channel,
        Instant createdAt,
        Instant expiresAt) implements Serializable {
    /**
     * Determines whether the challenge has exceeded its expiration threshold.
     *
     * @return {@code true} if current system time is past {@link #expiresAt}
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
