package com.sc.security_core.exception;

import com.sc.otp_core.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.jsonwebtoken.JwtException;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Centralized REST exception handler transforming application exceptions into
 * standardized RFC 7807 {@link ProblemDetail} responses for the frontend.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final URI BASE_ERROR_TYPE = URI.create("https://modelx.store/errors/");
	
	/**
	 * Handles Bad Passwords during login
	 */
	@ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentialsException(BadCredentialsException ex) {
		
        ProblemDetail problemDetail = ProblemDetail
        		.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        
        problemDetail.setTitle("Authentication Failed");
        problemDetail.setType(BASE_ERROR_TYPE.resolve("auth-failed"));
        problemDetail.setProperty("timestamp", Instant.now());
        
        return problemDetail;
        
    }
	
	/**
	 * Handles General Business Logic Errors (e.g. Email already exists)
	 */
	@ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgumentException(IllegalArgumentException ex) {
		
        ProblemDetail problemDetail = ProblemDetail
        		.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        
        problemDetail.setTitle("Bad Request");
        problemDetail.setType(BASE_ERROR_TYPE.resolve("bad-request"));
        problemDetail.setProperty("timestamp", Instant.now());
        
        return problemDetail;
        
    }
	
	/**
	 * Handles JWT Signature/Formatting Errors
	 */
	@ExceptionHandler(JwtException.class)
    public ProblemDetail handleJwtException(JwtException ex) {
		
        ProblemDetail problemDetail = ProblemDetail
        		.forStatusAndDetail(HttpStatus.FORBIDDEN, "Invalid or Malformed JWT Token");
        
        problemDetail.setTitle("Token Validation Failed");
        problemDetail.setProperty("timestamp", Instant.now());
        
        return problemDetail;
        
    }

    /**
     * Handles rate-limiting cooldown violations when requesting new OTPs.
     */
    @ExceptionHandler(OtpCooldownException.class)
    public ProblemDetail handleOtpCooldownException(OtpCooldownException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setTitle("Rate Limit Exceeded");
        problem.setType(BASE_ERROR_TYPE.resolve("rate-limited"));
        problem.setProperty("retryAfterSeconds", ex.getRemainingSeconds());
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles candidate code mismatches with attempt decrement feedback.
     */
    @ExceptionHandler(OtpInvalidException.class)
    public ProblemDetail handleOtpInvalidException(OtpInvalidException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Invalid Verification Code");
        problem.setType(BASE_ERROR_TYPE.resolve("otp-invalid"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles expired one-time passwords or stale MFA challenge sessions.
     */
    @ExceptionHandler(OtpExpiredException.class)
    public ProblemDetail handleOtpExpiredException(OtpExpiredException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Verification Code Expired");
        problem.setType(BASE_ERROR_TYPE.resolve("otp-expired"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles lockout after all allowed verification attempts have been exhausted.
     */
    @ExceptionHandler(OtpMaxAttemptsExceededException.class)
    public ProblemDetail handleOtpMaxAttemptsExceededException(OtpMaxAttemptsExceededException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, ex.getMessage());
        problem.setTitle("Maximum Attempts Exceeded");
        problem.setType(BASE_ERROR_TYPE.resolve("otp-exhausted"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Catch-all fallback for any other general OTP domain exceptions.
     */
    @ExceptionHandler(OtpException.class)
    public ProblemDetail handleGeneralOtpException(OtpException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        problem.setTitle("Verification Error");
        problem.setType(BASE_ERROR_TYPE.resolve("otp-error"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles missing user during secondary factor completion.
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ProblemDetail handleUsernameNotFoundException(UsernameNotFoundException ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "User account not found");
        problem.setTitle("Account Not Found");
        problem.setType(BASE_ERROR_TYPE.resolve("user-not-found"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles disabled or locked user accounts.
     */
    @ExceptionHandler({DisabledException.class, LockedException.class})
    public ProblemDetail handleAccountStatusException(Exception ex) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, ex.getMessage());
        problem.setTitle("Account Inactive");
        problem.setType(BASE_ERROR_TYPE.resolve("account-inactive"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Handles Jakarta Bean Validation errors (@Valid on request bodies).
     * Aggregates field errors into a readable map for frontend forms.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidationException(MethodArgumentNotValidException ex) {
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }
        String summary = fieldErrors.values().stream().findFirst().orElse("Invalid request payload");
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, summary);
        problem.setTitle("Validation Failed");
        problem.setType(BASE_ERROR_TYPE.resolve("validation-error"));
        problem.setProperty("errors", fieldErrors);
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }

    /**
     * Internal catch-all preventing raw JVM or SQL traces from leaking to clients.
     */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGenericException(Exception ex) {
        log.error("Unhandled exception caught in GlobalExceptionHandler", ex);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected internal error occurred. Please try again later."
        );
        problem.setTitle("Internal Server Error");
        problem.setType(BASE_ERROR_TYPE.resolve("server-error"));
        problem.setProperty("timestamp", Instant.now());
        return problem;
    }
}
