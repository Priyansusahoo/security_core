package com.sc.otp_core.storage.impl.jpa.entity;

import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "otp_sessions", indexes = {
        @Index(name = "idx_otp_target_purpose_active", columnList = "target, purpose, consumed, expires_at")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OtpEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String target;

    @Column(name = "hashed_otp", nullable = false)
    private String hashedOtp;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private OtpPurpose purpose;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private OtpChannel channel;

    @Column(name = "attempts_remaining", nullable = false)
    private int attemptsRemaining;

    @Column(nullable = false)
    private boolean consumed;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
