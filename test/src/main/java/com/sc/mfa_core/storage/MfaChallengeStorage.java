package com.sc.mfa_core.storage;

import com.sc.mfa_core.domain.MfaChallenge;

import java.time.Duration;
import java.util.Optional;

/**
 * Storage contract for persisting and retrieving ephemeral {@link MfaChallenge} instances.
 */
public interface MfaChallengeStorage {

    String KEY_PREFIX = "mfa:challenge:";

    /**
     * Persists an active challenge with a strict Time-To-Live.
     *
     * @param challengeToken The unique challenge ticket key
     * @param challenge      The challenge session details
     * @param ttl            Duration before the challenge automatically expires
     */
    void save(String challengeToken, MfaChallenge challenge, Duration ttl);

    /**
     * Retrieves an active challenge by its token if present and not expired.
     *
     * @param challengeToken The challenge ticket key
     * @return Optional containing the active challenge, or empty if missing/expired
     */
    Optional<MfaChallenge> find(String challengeToken);

    /**
     * Invalidate and evict the challenge immediately upon completion or cancellation.
     *
     * @param challengeToken The challenge ticket key
     */
    void remove(String challengeToken);
}