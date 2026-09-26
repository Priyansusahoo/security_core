package com.sc.otp_core.sender.impl;

import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.sender.OtpSender;
import com.sc.otp_core.template.OtpTemplateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

/**
 * SMTP implementation of {@link OtpSender} delivering codes via email.
 */
@Component
@RequiredArgsConstructor @Slf4j
public class SmtpEmailOtpSender implements OtpSender {

    private final JavaMailSender mailSender;
    private final OtpTemplateService templateService;

    @Value("${spring.mail.username}")
    private String fromEmail;

    /**
     * Asynchronously sends the one-time password via configured SMTP mail server.
     *
     * @param recipient Target email address, phone number, etc.
     * @param plainOtp  Plaintext one-time password
     * @param purpose   Purpose for the OTP dispatch (MFA, password reset)
     */
    @Async
    @Override
    public void send(String recipient, String plainOtp, OtpPurpose purpose) {
        String subject = templateService.resolveSubject(purpose);
        String body = templateService.resolveBody(plainOtp, purpose);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromEmail);
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(body);

        log.info("Sending OTP via EMAIL to: {} for purpose: {}", recipient, purpose);
        mailSender.send(message);
    }

    /**
     * Declares the channel supported by this sender (EMAIL, SMS, etc.).
     *
     * @return {@link OtpChannel#EMAIL}
     */
    @Override
    public OtpChannel supportsChannel() {
        return OtpChannel.EMAIL;
    }
}
