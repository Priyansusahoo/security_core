package com.sc.mfa_core.service.impl;

import com.sc.mfa_core.config.MfaProperties;
import com.sc.mfa_core.domain.MfaChallenge;
import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.mfa_core.dto.MfaVerificationResult;
import com.sc.mfa_core.service.MfaService;
import com.sc.mfa_core.storage.MfaChallengeStorage;
import com.sc.mfa_core.util.DestinationMasker;
import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.exception.OtpExpiredException;
import com.sc.otp_core.service.OtpService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * Production implementation of {@link MfaService}.
 * <p>
 * Orchestrates secondary factor challenges independently of application-level authentication.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaServiceImpl implements MfaService {

    private final OtpService otpService;
    private final MfaChallengeStorage challengeStorage;
    private final DestinationMasker destinationMasker;
    private final MfaProperties properties;

    /**
     * Initiates a new MFA challenge for a principal.
     *
     * @param target  The recipient destination (email address or phone number)
     * @param channel The delivery channel (e.g. {@link OtpChannel#EMAIL})
     * @return {@link MfaChallengeResponse} containing ticket and masked destination
     */
    @Override
    public MfaChallengeResponse initiateChallenge(String target, OtpChannel channel) {
        String normalizedTarget = target.toLowerCase().trim();

        String challengeToken = UUID.randomUUID().toString();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.getChallengeTtl());

        MfaChallenge challenge = MfaChallenge.builder()
                .challengeToken(challengeToken)
                .target(normalizedTarget)
                .channel(channel)
                .createdAt(now)
                .expiresAt(expiresAt)
                .build();

        challengeStorage.save(challengeToken, challenge, properties.getChallengeTtl());

        otpService.generateAndSend(normalizedTarget, OtpPurpose.MFA_LOGIN, channel);

        // Return channel-agnostic, masked response
        String masked = destinationMasker.mask(normalizedTarget, channel);
        log.info("Initiated MFA challenge [{}] for target: {}", challengeToken, masked);

        return MfaChallengeResponse.builder()
                .mfaRequired(true)
                .challengeToken(challengeToken)
                .channel(channel)
                .maskedDestination(masked)
                .message("Verification code dispatched successfully.")
                .build();
    }

    /**
     * Validates candidate OTP against active challenge ticket and evicts the challenge.
     *
     * @param request The verification payload containing ticket and candidate code
     * @return {@link MfaVerificationResult} containing the verified target identity and channel
     * @throws com.sc.otp_core.exception.OtpException if code is invalid, expired, or attempts exhausted
     */
    @Override
    public MfaVerificationResult verifyChallenge(MfaVerificationRequest request) {
        MfaChallenge challenge = challengeStorage.find(request.challengeToken())
                .orElseThrow(() -> new OtpExpiredException("MFA session has expired or is invalid. Please sign in again."));

        if (challenge.isExpired()) {
            challengeStorage.remove(request.challengeToken());
            throw new OtpExpiredException("MFA session has expired. Please sign in again.");
        }

        otpService.verify(challenge.target(), OtpPurpose.MFA_LOGIN, request.code());

        challengeStorage.remove(request.challengeToken());
        log.info("MFA challenge [{}] successfully verified for target: {}", request.challengeToken(), challenge.target());

        return new MfaVerificationResult(challenge.target(), challenge.channel());
    }

    /**
     * Re-issues and dispatches a fresh code for an active challenge session.
     *
     * @param request The resend payload containing the active ticket
     */
    @Override
    public void resendCode(MfaResendRequest request) {
        MfaChallenge challenge = challengeStorage.find(request.challengeToken())
                .orElseThrow(() -> new OtpExpiredException("MFA session has expired or is invalid. Please sign in again."));

        if (challenge.isExpired()) {
            challengeStorage.remove(request.challengeToken());
            throw new OtpExpiredException("MFA session has expired. Please sign in again.");
        }
        // Re-dispatch OTP through the existing channel
        otpService.generateAndSend(challenge.target(), OtpPurpose.MFA_LOGIN, challenge.channel());
        log.info("Resent MFA code for challenge [{}] via {}", request.challengeToken(), challenge.channel());
    }
}
