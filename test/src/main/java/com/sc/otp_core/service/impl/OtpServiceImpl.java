package com.sc.otp_core.service.impl;

import com.sc.otp_core.config.OtpProperties;
import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;
import com.sc.otp_core.exception.*;
import com.sc.otp_core.generator.OtpGenerator;
import com.sc.otp_core.sender.OtpSender;
import com.sc.otp_core.service.OtpService;
import com.sc.otp_core.storage.OtpStorage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * Production implementation of {@link OtpService}.
 * <p>
 * Implements HMAC-SHA256 digest hashing with server-side secrets,
 * strict resend throttling cooldowns, and constant-time equality validation.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private final OtpGenerator otpGenerator;
    private final OtpStorage otpStorage;
    private final List<OtpSender> otpSenders;
    private final OtpProperties properties;

    @Value("${application.security.jwt.secret}")
    private String hmacSecretKey;

    /**
     * Generates, securely hashes via HMAC-SHA256, caches with TTL, and dispatches an OTP.
     * Enforces the configured {@code resendCooldown} threshold to prevent abuse.
     *
     * @param recipient Target recipient (e.g. user email address)
     * @param purpose   Domain purpose for this code (e.g. MFA_LOGIN)
     * @param channel   Delivery channel (e.g. EMAIL)
     * @throws OtpException if a new request is made prior to cooldown expiry
     */
    @Override
    public void generateAndSend(String recipient, OtpPurpose purpose, OtpChannel channel) {
        String normalizedRecipient = recipient.toLowerCase().trim();

        // Enforce resend cooldown if an active unexpired session already exists
        otpStorage.find(normalizedRecipient, purpose).ifPresent(existingSession -> {
            if (!existingSession.isExpired()) {
                Instant cooldownThreshold = existingSession.createdAt().plus(properties.getResendCooldown());
                if (Instant.now().isBefore(cooldownThreshold)) {
                    long remainingSeconds = Duration.between(Instant.now(), cooldownThreshold).toSeconds();
                    throw new OtpCooldownException(Math.max(1, remainingSeconds));
                }
            }
        });

        // Pre-resolve sender to ensure dispatch capability BEFORE updating storage state
        OtpSender sender = otpSenders.stream()
                .filter(s -> s.supportsChannel() == channel)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No sender configured for channel: " + channel));

        String plainOtp = otpGenerator.generate(properties.getLength());
        String hashedOtp = computeHmac(plainOtp, normalizedRecipient, purpose);

        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getExpiration());

        OtpSession session = OtpSession.builder()
                .target(normalizedRecipient)
                .hashedOtp(hashedOtp)
                .purpose(purpose)
                .channel(channel)
                .attemptsRemaining(properties.getMaxAttempts())
                .createdAt(now)
                .expiresAt(expiresAt)
                .build();

        otpStorage.save(normalizedRecipient, purpose, session, properties.getExpiration());

        sender.send(normalizedRecipient, plainOtp, purpose);
    }

    /**
     * Verifies user candidate code against stored HMAC digest using constant-time comparison.
     *
     * @param recipient    Target recipient
     * @param purpose      Expected purpose
     * @param candidateOtp User submitted code
     * @return {@code true} if valid
     * @throws OtpException if expired, exhausted, or invalid
     */
    @Override
    public boolean verify(String recipient, OtpPurpose purpose, String candidateOtp) {
        String normalizedRecipient = recipient.toLowerCase().trim();

        OtpSession session = otpStorage.find(normalizedRecipient, purpose)
                .orElseThrow(() -> new OtpExpiredException("Verification code has expired or does not exist."));

        if (session.isExpired()) {
            otpStorage.remove(normalizedRecipient, purpose);
            throw new OtpExpiredException("Verification code has expired. Please request a new one.");
        }

        if (session.hasAttemptsExhausted()) {
            otpStorage.remove(normalizedRecipient, purpose);
            throw new OtpMaxAttemptsExceededException("Maximum verification attempts exceeded. Please request a new code.");
        }

        String candidateHash = computeHmac(candidateOtp.trim(), normalizedRecipient, purpose);
        boolean isMatch = MessageDigest.isEqual(
                session.hashedOtp().getBytes(StandardCharsets.UTF_8),
                candidateHash.getBytes(StandardCharsets.UTF_8)
        );

        if (!isMatch) {
            // Decrement remaining attempts and update cache
            OtpSession updatedSession = session.decrementAttempt();
            if (updatedSession.hasAttemptsExhausted()) {
                otpStorage.remove(normalizedRecipient, purpose);
                throw new OtpMaxAttemptsExceededException("Incorrect code. Maximum attempts exceeded. Code invalidated.");
            } else {
                otpStorage.save(normalizedRecipient, purpose, updatedSession, properties.getExpiration());
                throw new OtpInvalidException(String.format("Invalid code. %d attempts remaining.", updatedSession.attemptsRemaining()));
            }
        }
        otpStorage.remove(normalizedRecipient, purpose);
        log.info("OTP successfully verified and invalidated for target: {} [{}]", normalizedRecipient, purpose);
        return true;
    }

    /**
     * Computes HMAC-SHA256 digest binding candidate OTP to the principal and specific purpose.
     */
    private String computeHmac(String plainOtp, String target, OtpPurpose purpose) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hmacSecretKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            String payload = target + ":" + purpose.name() + ":" + plainOtp;
            byte[] rawHmac = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(rawHmac);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA256 digest for OTP", e);
        }
    }
}
