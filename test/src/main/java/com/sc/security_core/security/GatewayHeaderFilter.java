package com.sc.security_core.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Filter that validates that incoming requests originated from the trusted API Gateway.
 * Rejects direct client calls attempting to bypass the gateway with HTTP 403 Forbidden.
 */
@Slf4j
@Component
public class GatewayHeaderFilter extends OncePerRequestFilter {

    public static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";

    @Value("${application.gateway.shared-secret}")
    private String sharedSecret;

    @Value("${application.gateway.enforce-secret:true}")
    private boolean enforceSecret;

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        if (!enforceSecret) {
            return true;
        }
        // Browsers never send custom application headers on CORS OPTIONS preflight requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        // Allow internal health checks and error dispatching by bypass
        return path.startsWith("/actuator/health") || path.startsWith("/error");
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String incomingSecret = request.getHeader(GATEWAY_SECRET_HEADER);

        if (sharedSecret == null || sharedSecret.isBlank() || incomingSecret == null ||
                !MessageDigest.isEqual(incomingSecret.getBytes(StandardCharsets.UTF_8), sharedSecret.getBytes(StandardCharsets.UTF_8))) {

            log.warn("Blocked direct access attempt to [{}] from remote address [{}] without valid gateway secret",
                    request.getRequestURI(), request.getRemoteAddr());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("""
                {
                    "status": 403,
                    "error": "Forbidden",
                    "message": "Direct access forbidden: all client requests must pass through the API Gateway."
                }
                """);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
