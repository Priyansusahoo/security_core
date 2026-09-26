package com.sc.mfa_core.storage.impl.jpa;

import com.sc.mfa_core.domain.MfaChallenge;
import com.sc.mfa_core.storage.MfaChallengeStorage;
import com.sc.mfa_core.storage.impl.jpa.entity.MfaChallengeEntity;
import com.sc.mfa_core.storage.impl.jpa.repository.MfaChallengeJpaRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Relational database implementation of {@link MfaChallengeStorage} using Spring Data JPA.
 * <p>
 * Automatically activated when {@code application.security.mfa.storage-type} is set to {@code DB}
 * or omitted by default.
 * </p>
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "application.security.mfa.storage-type", havingValue = "DB", matchIfMissing = true)
@RequiredArgsConstructor
public class JpaMfaChallengeStorage implements MfaChallengeStorage {

    private final MfaChallengeJpaRepository repository;

    /**
     * Persists an active challenge with a strict Time-To-Live.
     *
     * @param challengeToken The unique challenge ticket key
     * @param challenge      The challenge session details
     * @param ttl            Duration before the challenge automatically expires
     */
    @Override
    @Transactional
    public void save(String challengeToken, MfaChallenge challenge, Duration ttl) {
        String normalizedTarget = challenge.target().toLowerCase().trim();
        // Invalidate any existing tickets for this target before creating a fresh challenge
        repository.deleteByTarget(normalizedTarget);

        MfaChallengeEntity entity = MfaChallengeEntity.builder()
                .challengeToken(challengeToken)
                .target(normalizedTarget)
                .channel(challenge.channel())
                .createdAt(challenge.createdAt())
                .expiresAt(challenge.expiresAt())
                .build();

        repository.save(entity);
        log.debug("Persisted MFA challenge in DB for target: {} [Ticket: {}]", normalizedTarget, challengeToken);
    }

    /**
     * Retrieves an active challenge by its token if present and not expired.
     *
     * @param challengeToken The challenge ticket key
     * @return Optional containing the active challenge, or empty if missing/expired
     */
    @Override
    @Transactional
    public Optional<MfaChallenge> find(String challengeToken) {
        return repository.findById(challengeToken)
                .filter(entity -> {
                    if (Instant.now().isAfter(entity.getExpiresAt())) {
                        repository.delete(entity);
                        return false;
                    }
                    return true;
                })
                .map(entity -> MfaChallenge.builder()
                        .challengeToken(entity.getChallengeToken())
                        .target(entity.getTarget())
                        .channel(entity.getChannel())
                        .createdAt(entity.getCreatedAt())
                        .expiresAt(entity.getExpiresAt())
                        .build()
                );
    }

    /**
     * Invalidate and evict the challenge immediately upon completion or cancellation.
     *
     * @param challengeToken The challenge ticket key
     */
    @Override
    @Transactional
    public void remove(String challengeToken) {
        repository.deleteById(challengeToken);
        log.debug("Evicted MFA challenge ticket from DB: {}", challengeToken);
    }
}
