package com.sc.otp_core.exception;

public class OtpMaxAttemptsExceededException extends OtpException {
    public OtpMaxAttemptsExceededException(String message) {
        super(message);
    }
}
