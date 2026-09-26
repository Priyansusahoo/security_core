package com.sc.mfa_core.storage.impl;

import com.sc.mfa_core.domain.MfaChallenge;
import com.sc.mfa_core.storage.MfaChallengeStorage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

/**
 * Redis-backed implementation of {@link MfaChallengeStorage}.
 * Uses native Redis key-level TTL expiration.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "application.security.mfa.storage-type", havingValue = "REDIS")
@RequiredArgsConstructor
public class RedisMfaChallengeStorage implements MfaChallengeStorage {

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Persists an active challenge with a strict Time-To-Live.
     *
     * @param challengeToken The unique challenge ticket key
     * @param challenge      The challenge session details
     * @param ttl            Duration before the challenge automatically expires
     */
    @Override
    public void save(String challengeToken, MfaChallenge challenge, Duration ttl) {
        String key = KEY_PREFIX + challengeToken;
        redisTemplate.opsForValue().set(key, challenge, ttl);
        log.debug("Persisted MFA challenge in Redis with key: {} [TTL: {}s]", key, ttl.toSeconds());
    }

    /**
     * Retrieves an active challenge by its token if present and not expired.
     *
     * @param challengeToken The challenge ticket key
     * @return Optional containing the active challenge, or empty if missing/expired
     */
    @Override
    public Optional<MfaChallenge> find(String challengeToken) {
        String key = KEY_PREFIX + challengeToken;
        Object val = redisTemplate.opsForValue().get(key);
        if (val instanceof MfaChallenge challenge) {
            return Optional.of(challenge);
        }
        return Optional.empty();
    }

    /**
     * Invalidate and evict the challenge immediately upon completion or cancellation.
     *
     * @param challengeToken The challenge ticket key
     */
    @Override
    public void remove(String challengeToken) {
        String key = KEY_PREFIX + challengeToken;
        redisTemplate.delete(key);
        log.debug("Evicted MFA challenge from Redis: {}", key);
    }
}