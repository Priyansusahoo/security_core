package com.sc.otp_core.storage.impl.jpa.repository;

import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.storage.impl.jpa.entity.OtpEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface OtpJpaRepository extends JpaRepository<OtpEntity, Long> {

    /**
     * Finds the latest active unconsumed OTP session.
     */
    Optional<OtpEntity> findTopByTargetAndPurposeAndConsumedFalseOrderByCreatedAtDesc(String target, OtpPurpose purpose);

    /**
     * Marks all active OTPs for this target and purpose as consumed/invalidated.
     */
    @Modifying
    @Query("UPDATE OtpEntity o SET o.consumed = true WHERE o.target = :target AND o.purpose = :purpose AND o.consumed = false")
    void invalidateAllActive(@Param("target") String target, @Param("purpose") OtpPurpose purpose);

    /**
     * Cleanup old expired/consumed records.
     */
    @Modifying
    @Query("DELETE FROM OtpEntity o WHERE o.expiresAt < :now OR o.consumed = true")
    void deleteExpiredOrConsumed(@Param("now") Instant now);
}
