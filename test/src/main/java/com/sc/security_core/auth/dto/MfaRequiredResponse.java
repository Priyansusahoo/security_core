package com.sc.security_core.auth.dto;

import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.otp_core.domain.OtpChannel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

/**
 * Response payload returned when primary credentials are valid but MFA is required.
 */
@Builder
@Schema(description = "Response returned when Multi-Factor Authentication is required to complete login.")
public record MfaRequiredResponse(
        @Schema(description = "Whether MFA is required", example = "true")
        boolean mfaRequired,
        @Schema(description = "Ephemeral challenge token for verifying or resending OTP")
        String challengeToken,
        @Schema(description = "OTP delivery channel (e.g. EMAIL, SMS)")
        OtpChannel channel,
        @Schema(description = "Masked target where code was sent", example = "p***@gmail.com")
        String maskedDestination,
        @Schema(description = "Informational message for the user")
        String message
) implements LoginResponse {
    /**
     * Converts a core MfaChallengeResponse into this web-facing MfaRequiredResponse.
     */
    public static MfaRequiredResponse from(MfaChallengeResponse challenge) {
        return new MfaRequiredResponse(
                challenge.mfaRequired(),
                challenge.challengeToken(),
                challenge.channel(),
                challenge.maskedDestination(),
                challenge.message()
        );
    }
}