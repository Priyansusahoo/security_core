package com.sc.security_core.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Sealed interface representing the outcome of an authentication attempt.
 * <p>
 * Permits only two specific response types:
 * <ul>
 *   <li>{@link AuthResponse} - Full authentication succeeded; JWT token issued.</li>
 *   <li>{@link MfaRequiredResponse} - Credentials valid; secondary MFA factor challenge required.</li>
 * </ul>
 */
@Schema(
        description = "Authentication response: either full JWT tokens or an MFA challenge requirement.",
        subTypes = {AuthResponse.class, MfaRequiredResponse.class}
)
public sealed interface LoginResponse permits AuthResponse, MfaRequiredResponse {
}
