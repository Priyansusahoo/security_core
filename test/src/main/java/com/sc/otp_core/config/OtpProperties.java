package com.sc.otp_core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Getter @Setter
@Configuration
@ConfigurationProperties(prefix = "application.security.otp")
public class OtpProperties {

    /**
     * Number of digits in the OTP (default 6).
     */
    private int length = 6;

    /**
     * How long the OTP remains valid (default 5 minutes).
     */
    private Duration expiration = Duration.ofMinutes(5);

    /**
     * Maximum failed verification attempts before invalidating (default 3).
     */
    private int maxAttempts = 3;

    /**
     * Rate limit: minimum seconds to wait before requesting a new OTP (default 60s).
     */
    private Duration resendCooldown = Duration.ofSeconds(60);

    public enum StorageType {
        DB,
        REDIS,
        MEMORY
    }

    private StorageType storageType = StorageType.DB;
}
