package com.sc.otp_core.storage.impl;

import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;
import com.sc.otp_core.storage.OtpStorage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Slf4j
@Component
@ConditionalOnBean(RedisTemplate.class)
@RequiredArgsConstructor
public class RedisOtpStorage implements OtpStorage {

    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * Persists an OTP session with a specific Time-To-Live (TTL).
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     * @param session {@link OtpSession}
     * @param ttl valid till duration
     */
    @Override
    public void save(String target, OtpPurpose purpose, OtpSession session, Duration ttl) {
        String key = buildKey(target, purpose);
        redisTemplate.opsForValue().set(key, session, ttl);
        log.debug("Saved OTP session in Redis for key: {} with TTL: {}s", key, ttl.toSeconds());
    }

    /**
     * Retrieves an active OTP session if present and not expired.
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     */
    @Override
    public Optional<OtpSession> find(String target, OtpPurpose purpose) {
        String key = buildKey(target, purpose);
        Object value = redisTemplate.opsForValue().get(key);

        if (value instanceof OtpSession session) {
            return Optional.of(session);
        }
        return Optional.empty();
    }

    /**
     * Removes/invalidates the OTP session immediately (e.g. upon successful verification).
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     */
    @Override
    public void remove(String target, OtpPurpose purpose) {
        String key = buildKey(target, purpose);
        redisTemplate.delete(key);
        log.debug("Evicted OTP session from Redis for key: {}", key);
    }
}
