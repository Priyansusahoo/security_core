package com.sc.otp_core.exception;

import lombok.Getter;

/**
 * Thrown when an OTP generation request violates the configured resend cooldown window.
 */
@Getter
public class OtpCooldownException extends OtpException {

    private final long remainingSeconds;

    /**
     * Constructs a new cooldown exception with the calculated remaining wait time.
     *
     * @param remainingSeconds Seconds the user must wait before resending
     */
    public OtpCooldownException(long remainingSeconds) {
        super(String.format("Please wait %d seconds before requesting another code.", Math.max(1, remainingSeconds)));
        this.remainingSeconds = remainingSeconds;
    }

    public OtpCooldownException(String message) {
        super(message);
        this.remainingSeconds = 0;
    }
}
