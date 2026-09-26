package com.sc.mfa_core.service;

import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.mfa_core.dto.MfaVerificationResult;
import com.sc.otp_core.domain.OtpChannel;

/**
 * Core orchestration service for Multi-Factor Authentication challenge lifecycles.
 * <p>
 * Completely decoupled from user persistence and token generation.
 * </p>
 */
public interface MfaService {

    /**
     * Initiates a new MFA challenge for a principal.
     *
     * @param target  The recipient destination (email address or phone number)
     * @param channel The delivery channel (e.g. {@link OtpChannel#EMAIL})
     * @return {@link MfaChallengeResponse} containing ticket and masked destination
     */
    MfaChallengeResponse initiateChallenge(String target, OtpChannel channel);

    /**
     * Validates candidate OTP against active challenge ticket and evicts the challenge.
     *
     * @param request The verification payload containing ticket and candidate code
     * @return {@link MfaVerificationResult} containing the verified target identity and channel
     * @throws com.sc.otp_core.exception.OtpException if code is invalid, expired, or attempts exhausted
     */
    MfaVerificationResult verifyChallenge(MfaVerificationRequest request);

    /**
     * Re-issues and dispatches a fresh code for an active challenge session.
     *
     * @param request The resend payload containing the active ticket
     */
    void resendCode(MfaResendRequest request);
}