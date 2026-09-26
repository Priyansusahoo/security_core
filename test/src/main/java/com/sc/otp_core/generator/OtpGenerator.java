package com.sc.otp_core.generator;

public interface OtpGenerator {
    /**
     * Generates a numeric OTP of specified length.
     *
     * @param length Number of digits (e.g., 6)
     * @return Generated numeric string (e.g., "482910")
     */
    String generate(int length);
}