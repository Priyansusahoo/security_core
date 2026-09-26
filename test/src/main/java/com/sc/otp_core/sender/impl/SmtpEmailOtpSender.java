package com.sc.otp_core.sender.impl;

import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.sender.OtpSender;
import com.sc.otp_core.template.OtpTemplateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor @Slf4j
@ConditionalOnBean(JavaMailSender.class)
public class SmtpEmailOtpSender implements OtpSender {

    private final JavaMailSender mailSender;
    private final OtpTemplateService templateService;

    @Value("${spring.mail.username}")
    private String fromEmail;
    /**
     * Sends the OTP to the recipient.
     *
     * @param recipient Target email address or phone number
     * @param plainOtp  Plaintext OTP to deliver
     * @param purpose   Reason for OTP (MFA, password reset)
     */
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
     */
    @Override
    public OtpChannel supportsChannel() {
        return OtpChannel.EMAIL;
    }
}
