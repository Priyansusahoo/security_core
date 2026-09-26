package com.sc.mfa_core.util.impl;

import com.sc.mfa_core.util.DestinationMasker;
import com.sc.otp_core.domain.OtpChannel;
import org.springframework.stereotype.Component;

/**
 * Default implementation of {@link DestinationMasker} supporting standard channels.
 */
@Component
public class DefaultDestinationMasker implements DestinationMasker {

    @Override
    public String mask(String destination, OtpChannel channel) {
        if (destination == null || destination.isBlank()) {
            return "";
        }
        return switch (channel) {
            case EMAIL -> maskEmail(destination.trim());
            case SMS -> maskPhone(destination.trim());
        };
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) {
            return email; // Malformed or single character username
        }
        String username = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        if (username.length() <= 2) {
            return username.charAt(0) + "***" + domain;
        }
        return username.charAt(0) + "***" + username.charAt(username.length() - 1) + domain;
    }

    private String maskPhone(String phone) {
        if (phone.length() <= 4) {
            return "****";
        }
        // Shows only the last 4 digits: e.g. "******4819"
        return "*".repeat(phone.length() - 4) + phone.substring(phone.length() - 4);
    }
}
