package com.sc.otp_core.generator.impl;

import com.sc.otp_core.generator.OtpGenerator;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class SecureRandomOtpGenerator implements OtpGenerator {

    private final SecureRandom secureRandom =  new SecureRandom();

    /**
     * Generates a numeric OTP of specified length.
     *
     * @param length Number of digits (e.g. 6)
     * @return Numeric OTP string
     * @throws IllegalArgumentException if length is not between 1 and 32
     */
    @Override
    public String generate(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("OTP length must be between 1 and 32 digits");
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(secureRandom.nextInt(10));
        }
        return sb.toString();
    }
}
