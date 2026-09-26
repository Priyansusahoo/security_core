package com.sc.mfa_core.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Configuration properties for Multi-Factor Authentication workflows.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "application.security.mfa")
public class MfaProperties {

    /**
     * Whether Multi-Factor Authentication is globally enforced or enabled.
     */
    private boolean enabled = true;

    /**
     * Time-to-live duration for an active MFA challenge ticket (default 5 minutes).
     */
    private Duration challengeTtl = Duration.ofMinutes(5);

    public enum StorageType {
        DB,
        REDIS,
        MEMORY
    }
    /**
     * Persistence strategy for MFA challenge tickets (default DB).
     */
    private StorageType storageType = StorageType.DB;
}