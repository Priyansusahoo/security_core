package com.sc.otp_core.service;

import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;

public interface OtpService {

    /**
     * Generates, securely hashes, caches with TTL, and dispatches an OTP.
     *
     * @param recipient Target recipient (e.g. email)
     * @param purpose MFA_LOGIN or PASSWORD_RESET
     * @param channel Delivery channel (EMAIL)
     */
    void generateAndSend(String recipient, OtpPurpose purpose, OtpChannel channel);

    /**
     * Verifies user-entered OTP against the stored hashed OTP.
     * Decrements attempts on failure, invalidates session on success.
     *
     * @param recipient Target recipient
     * @param purpose Expected purpose
     * @param candidateOtp User input code
     * @return true if valid
     * @throws com.sc.otp_core.exception.OtpException if expired, exhausted, or invalid
     */
    boolean verify(String recipient, OtpPurpose purpose, String candidateOtp);
}
