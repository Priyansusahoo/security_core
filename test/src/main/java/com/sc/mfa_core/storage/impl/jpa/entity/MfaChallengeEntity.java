package com.sc.mfa_core.storage.impl.jpa.entity;

import com.sc.otp_core.domain.OtpChannel;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * JPA entity representing a persisted Multi-Factor Authentication challenge ticket.
 */
@Entity
@Table(name = "mfa_challenges", indexes = {
        @Index(name = "idx_mfa_challenges_target", columnList = "target"),
        @Index(name = "idx_mfa_challenges_expires_at", columnList = "expires_at")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MfaChallengeEntity {
    @Id
    @Column(name = "challenge_token", length = 64, nullable = false)
    private String challengeToken;
    @Column(nullable = false)
    private String target;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private OtpChannel channel;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
