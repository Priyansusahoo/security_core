package com.sc.otp_core.storage.impl.jpa;

import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;
import com.sc.otp_core.storage.OtpStorage;
import com.sc.otp_core.storage.impl.jpa.entity.OtpEntity;
import com.sc.otp_core.storage.impl.jpa.repository.OtpJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Component
@ConditionalOnProperty(name = "application.security.otp.storage-type", havingValue = "DB", matchIfMissing = true)
@RequiredArgsConstructor
public class JpaOtpStorage implements OtpStorage {

    private final OtpJpaRepository repository;

    /**
     * Persists an OTP session with a specific Time-To-Live (TTL).
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     * @param session {@link OtpSession}
     * @param ttl valid till duration
     */
    @Override
    @Transactional
    public void save(String target, OtpPurpose purpose, OtpSession session, Duration ttl) {
        String normalizedTarget = target.toLowerCase().trim();

        repository.invalidateAllActive(normalizedTarget, purpose);

        OtpEntity entity = OtpEntity.builder()
                .target(normalizedTarget)
                .hashedOtp(session.hashedOtp())
                .purpose(purpose)
                .channel(session.channel())
                .attemptsRemaining(session.attemptsRemaining())
                .consumed(false)
                .createdAt(session.createdAt())
                .expiresAt(session.expiresAt())
                .build();
        repository.save(entity);
        log.debug("Persisted OTP session in DB for target: {} [{}]", normalizedTarget, purpose);
    }

    /**
     * Retrieves an active OTP session if present and not expired.
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     */
    @Override
    @Transactional(readOnly = true)
    public Optional<OtpSession> find(String target, OtpPurpose purpose) {
        String normalizedTarget = target.toLowerCase().trim();
        return repository.findTopByTargetAndPurposeAndConsumedFalseOrderByCreatedAtDesc(normalizedTarget, purpose)
                .filter(entity -> !entity.isConsumed() && Instant.now().isBefore(entity.getExpiresAt()))
                .map(entity -> OtpSession.builder()
                        .target(entity.getTarget())
                        .hashedOtp(entity.getHashedOtp())
                        .purpose(entity.getPurpose())
                        .channel(entity.getChannel())
                        .attemptsRemaining(entity.getAttemptsRemaining())
                        .createdAt(entity.getCreatedAt())
                        .expiresAt(entity.getExpiresAt())
                        .build()
                );
    }

    /**
     * Removes/invalidates the OTP session immediately (e.g. upon successful verification).
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     */
    @Override
    @Transactional
    public void remove(String target, OtpPurpose purpose) {
        String normalizedTarget = target.toLowerCase().trim();
        repository.invalidateAllActive(normalizedTarget, purpose);
        log.debug("Invalidated active OTP sessions in DB for target: {} [{}]", normalizedTarget, purpose);
    }
}
