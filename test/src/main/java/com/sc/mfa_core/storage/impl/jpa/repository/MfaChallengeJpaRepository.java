package com.sc.mfa_core.storage.impl.jpa.repository;

import com.sc.mfa_core.storage.impl.jpa.entity.MfaChallengeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;

/**
 * Spring Data JPA repository for {@link MfaChallengeEntity}.
 */
@Repository
public interface MfaChallengeJpaRepository extends JpaRepository<MfaChallengeEntity, String> {

    /**
     * Purges previous active challenges for the specified recipient to prevent stale tickets.
     *
     * @param target recipient identifier (email or phone)
     */
    @Modifying
    @Query("DELETE FROM MfaChallengeEntity m WHERE m.target = :target")
    void deleteByTarget(@Param("target") String target);

    /**
     * Purges all expired challenge records past the threshold timestamp.
     *
     * @param now current timestamp threshold
     */
    @Modifying
    @Query("DELETE FROM MfaChallengeEntity m WHERE m.expiresAt < :now")
    void deleteExpired(@Param("now") Instant now);
}
