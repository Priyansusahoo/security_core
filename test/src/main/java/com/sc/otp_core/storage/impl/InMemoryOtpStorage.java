package com.sc.otp_core.storage.impl;


import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;
import com.sc.otp_core.storage.OtpStorage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
@ConditionalOnMissingBean(RedisOtpStorage.class)
public class InMemoryOtpStorage implements OtpStorage {

    private final Map<String, OtpSession> cache = new ConcurrentHashMap<>();

    /**
     * Persists an OTP session with a specific Time-To-Live (TTL).
     *
     * @param target user-email, phone no.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc,.
     * @param session {@link OtpSession}
     * @param ttl valid till duration
     */
    @Override
    public void save(String target, OtpPurpose purpose, OtpSession session, Duration ttl) {
        String key = buildKey(target, purpose);
        cache.put(key, session);
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
        OtpSession session = cache.get(key);
        if (session != null && session.isExpired()) {
            cache.remove(key);
            return Optional.empty();
        }
        return Optional.ofNullable(session);
    }

    /**
     * Removes/invalidates the OTP session immediately (e.g. upon successful verification).
     *
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     */
    @Override
    public void remove(String target, OtpPurpose purpose) {
        cache.remove(buildKey(target, purpose));
    }
}
