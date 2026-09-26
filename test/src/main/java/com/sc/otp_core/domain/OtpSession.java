package com.sc.otp_core.domain;

import lombok.Builder;

import java.io.Serializable;
import java.time.Instant;

@Builder(toBuilder = true)
public record OtpSession(
        String target, // e.g. user-email
        String hashedOtp,
        OtpPurpose purpose,
        OtpChannel channel,
        int attemptsRemaining,
        Instant createdAt,
        Instant expiresAt) implements Serializable {

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean hasAttemptsExhausted() {
        return attemptsRemaining <= 0;
    }

    public OtpSession decrementAttempt() {
        return this.toBuilder()
                .attemptsRemaining(this.attemptsRemaining - 1)
                .build();
    }
}
