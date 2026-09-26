package com.sc.otp_core.storage;

import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.domain.OtpSession;

import java.time.Duration;
import java.util.Optional;

public interface OtpStorage {

    String KEY_PREFIX = "OTP:";

    /**
     * Persists an OTP session with a specific Time-To-Live (TTL).
     */
    void save(String target, OtpPurpose purpose, OtpSession session, Duration ttl);

    /**
     * Retrieves an active OTP session if present and not expired.
     */
    Optional<OtpSession> find(String target, OtpPurpose purpose);

    /**
     * Removes/invalidates the OTP session immediately (e.g. upon successful verification).
     */
    void remove(String target, OtpPurpose purpose);

    /**
     * @param target user-email, phone no., etc.
     * @param purpose {@link OtpPurpose} e.g. MFA, PASSWORD_RESET, etc.
     * @return e.g. "OTP:MFA_LOGIN:john@example.com"
     */
    default String buildKey(String target, OtpPurpose purpose) {
        return KEY_PREFIX + purpose.name() + ":" + target.toLowerCase().trim();
    }
}
