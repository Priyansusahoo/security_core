package com.sc.otp_core.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum OtpPurpose {

    MFA_LOGIN(
            "Two-Factor Authentication",
            "Your ModelX Verification Code"
    ),
    PASSWORD_RESET(
            "Password Reset",
            "ModelX Password Reset Request"
    ),
    EMAIL_VERIFICATION(
            "Email Verification",
            "Verify Your ModelX Email"
    );

    private final String displayName;
    private final String emailSubject;
}
