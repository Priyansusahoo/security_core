package com.sc.otp_core.sender;

import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;

public interface OtpSender {

    /**
     * Sends the OTP to the recipient.
     *
     * @param recipient Target email address or phone number
     * @param plainOtp Plaintext OTP to deliver
     * @param purpose Reason for OTP (MFA, password reset)
     */
    void send(String recipient, String plainOtp, OtpPurpose purpose);

    /**
     * Declares the channel supported by this sender (EMAIL, SMS, etc.).
     */
    OtpChannel supportsChannel();
}
