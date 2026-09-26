package com.sc.mfa_core.storage.impl;

import com.sc.mfa_core.domain.MfaChallenge;
import com.sc.mfa_core.storage.MfaChallengeStorage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory fallback implementation of {@link MfaChallengeStorage}.
 * Automatically activated when Redis is not present in the runtime context.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "application.security.mfa.storage-type", havingValue = "MEMORY")
public class InMemoryMfaChallengeStorage implements MfaChallengeStorage {

    private final Map<String, MfaChallenge> cache = new ConcurrentHashMap<>();

    /**
     * Persists an active challenge with a strict Time-To-Live.
     *
     * @param challengeToken The unique challenge ticket key
     * @param challenge      The challenge session details
     * @param ttl            Duration before the challenge automatically expires
     */
    @Override
    public void save(String challengeToken, MfaChallenge challenge, Duration ttl) {
        cache.put(challengeToken, challenge);
    }

    /**
     * Retrieves an active challenge by its token if present and not expired.
     *
     * @param challengeToken The challenge ticket key
     * @return Optional containing the active challenge, or empty if missing/expired
     */
    @Override
    public Optional<MfaChallenge> find(String challengeToken) {
        MfaChallenge challenge = cache.get(challengeToken);
        if (challenge != null && challenge.isExpired()) {
            cache.remove(challengeToken);
            return Optional.empty();
        }
        return Optional.ofNullable(challenge);
    }

    /**
     * Invalidate and evict the challenge immediately upon completion or cancellation.
     *
     * @param challengeToken The challenge ticket key
     */
    @Override
    public void remove(String challengeToken) {
        cache.remove(challengeToken);
    }
}
