package com.sc.otp_core.service.impl;

import com.sc.otp_core.config.OtpProperties;
import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;
import com.sc.otp_core.exception.OtpException;
import com.sc.otp_core.exception.OtpExpiredException;
import com.sc.otp_core.exception.OtpInvalidException;
import com.sc.otp_core.exception.OtpMaxAttemptsExceededException;
import com.sc.otp_core.generator.OtpGenerator;
import com.sc.otp_core.sender.OtpSender;
import com.sc.otp_core.service.OtpService;
import com.sc.otp_core.storage.OtpStorage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private final OtpGenerator otpGenerator;
    private final OtpStorage otpStorage;
    private final List<OtpSender> otpSenders;
    private final OtpProperties properties;
    /**
     * Generates, securely hashes, caches with TTL, and dispatches an OTP.
     *
     * @param recipient Target recipient (e.g. email)
     * @param purpose   MFA_LOGIN or PASSWORD_RESET
     * @param channel   Delivery channel (EMAIL)
     */
    @Override
    public void generateAndSend(String recipient, OtpPurpose purpose, OtpChannel channel) {
        String normalizedRecipient = recipient.toLowerCase().trim();

        String plainOtp = otpGenerator.generate(properties.getLength());
        String hashedOtp = hashOtp(plainOtp);

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

        OtpSender sender = otpSenders.stream()
                .filter(s -> s.supportsChannel() == channel)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No sender configured for channel: " + channel));

        sender.send(normalizedRecipient, plainOtp, purpose);
    }

    /**
     * Verifies user-entered OTP against the stored hashed OTP.
     * Decrements attempts on failure, invalidates session on success.
     *
     * @param recipient    Target recipient
     * @param purpose      Expected purpose
     * @param candidateOtp User input code
     * @return true if valid
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

        String candidateHash = hashOtp(candidateOtp.trim());
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

    private String hashOtp(String plainOtp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(plainOtp.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
