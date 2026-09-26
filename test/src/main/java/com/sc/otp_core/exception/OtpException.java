package com.sc.otp_core.exception;

public abstract class OtpException extends RuntimeException {
    protected OtpException(String message) {
        super(message);
    }
}
