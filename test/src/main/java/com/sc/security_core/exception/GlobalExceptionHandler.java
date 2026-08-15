package com.sc.security_core.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.jsonwebtoken.JwtException;

import java.net.URI;
import java.time.Instant;

@RestControllerAdvice
public class GlobalExceptionHandler {
	
	/**
	 * Handles Bad Passwords during login
	 */
	@ExceptionHandler(BadCredentialsException.class)
    public ProblemDetail handleBadCredentialsException(BadCredentialsException ex) {
		
        ProblemDetail problemDetail = ProblemDetail
        		.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid email or password");
        
        problemDetail.setTitle("Authentication Failed");
        problemDetail.setType(
        		URI.create("https://easybyte.com/errors/auth-failed")
        );
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
}
