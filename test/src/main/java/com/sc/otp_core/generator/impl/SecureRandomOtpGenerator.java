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
     * @param length Number of digits (e.g., 6)
     * @return Generated numeric string (e.g., "482910")
     */
    @Override
    public String generate(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("OTP length must be greater than 0");
        }
        int bound = (int) Math.pow(10, length);
        int number = secureRandom.nextInt(bound);

        return String.format("%0" + length + "d", number);
    }
}
