package com.sc.otp_core.template;

import com.sc.otp_core.config.OtpProperties;
import com.sc.otp_core.domain.OtpPurpose;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OtpTemplateService {
    private final OtpProperties properties;

    public String resolveSubject(OtpPurpose purpose) {
        return purpose.getEmailSubject();
    }

    public String resolveBody(String plainOtp, OtpPurpose purpose) {
        long minutes = properties.getExpiration().toMinutes();
        String expiryText = minutes > 0
                ? minutes + " minutes"
                : properties.getExpiration().toSeconds() + " seconds";
        return String.format(
                "Hello,\n\n" +
                        "Your one-time verification code for %s is:\n\n" +
                        "   %s\n\n" +
                        "This code will expire in %s. If you did not request this, please ignore this email.\n\n" +
                        "— The ModelX Security Team",
                purpose.getDisplayName(),
                plainOtp,
                expiryText
        );
    }
}
