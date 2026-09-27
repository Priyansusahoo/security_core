package com.sc.security_core.auth;

import com.sc.mfa_core.config.MfaProperties;
import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.mfa_core.dto.MfaVerificationResult;
import com.sc.mfa_core.service.MfaService;
import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.service.OtpService;
import com.sc.security_core.auth.dto.*;
import com.sc.security_core.security.JwtService;
import com.sc.security_core.user.Role;
import com.sc.security_core.user.User;
import com.sc.security_core.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final MfaProperties mfaProperties;
    private final MfaService mfaService;
    private final OtpService otpService;

    public Map<String, Object> register(RegisterRequest request) {
    	
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered!");
        }
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .enabled(false)
                .build();

        userRepository.save(user);

        otpService.generateAndSend(user.getEmail(), OtpPurpose.EMAIL_VERIFICATION, OtpChannel.EMAIL);
        log.info("Dispatched registration email verification OTP to {}", user.getEmail());

        return Map.of(
                "message", "Verification code sent to your email. Please verify to complete registration.",
                "email", user.getEmail(),
                "verificationRequired", true
        );
    }

    public LoginResponse login(LoginRequest request) {
    	
    	log.info("Attempting to authenticate user with email: {}", request.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        if (mfaProperties.isEnabled() /* && user.isMfaEnabled() */) {
            MfaChallengeResponse challenge = mfaService.initiateChallenge(user.getEmail(), OtpChannel.EMAIL);
            // Return MfaChallengeResponse instead of the JWT token
            return MfaRequiredResponse.from(challenge);
        }
        var jwtToken = jwtService.generateToken(user);
        log.info("User {} authenticated successfully. Generating JWT.", user.getEmail());

        return AuthResponse.builder()
                .token(jwtToken)
                .message("Login successful!")
                .build();
    }

    /**
     * Completes authentication following a successful MFA challenge validation.
     *
     * @param request Verification request containing challenge ticket and candidate code
     * @return Finalized {@link AuthResponse} containing the issued JWT
     */
    public AuthResponse verifyMfa(MfaVerificationRequest request) {
        MfaVerificationResult result = mfaService.verifyChallenge(request);
        User user = userRepository.findByEmail(result.target())
                .orElseThrow(() -> new UsernameNotFoundException("User not found for target: " + result.target()));
        String jwtToken = jwtService.generateToken(user);
        log.info("User [{}] successfully completed MFA verification. JWT issued.", user.getEmail());
        return AuthResponse.builder()
                .token(jwtToken)
                .message("Login successful!")
                .build();
    }
    /**
     * Dispatches a fresh verification code for an existing MFA challenge.
     *
     * @param request Payload containing the active challenge ticket
     */
    public void resendMfa(MfaResendRequest request) {
        mfaService.resendCode(request);
    }

    /**
     * Validates the email OTP, activates the user account, and issues the JWT token.
     */
    public AuthResponse verifyEmail(EmailVerificationRequest request) {
        // 1. Verify candidate OTP against HMAC-SHA256 in OtpService
        otpService.verify(request.email(), OtpPurpose.EMAIL_VERIFICATION, request.code());
        // 2. Activate the user account
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.email()));
        user.setEnabled(true);
        userRepository.save(user);
        // 3. Mint JWT token
        String jwtToken = jwtService.generateToken(user);
        log.info("User [{}] successfully verified email. Account enabled and JWT issued.", user.getEmail());
        return AuthResponse.builder()
                .token(jwtToken)
                .message("Email verified successfully! Registration complete.")
                .build();
    }
    /**
     * Dispatches a fresh verification OTP for unverified registrations.
     */
    public void resendEmailVerification(EmailResendRequest request) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.email()));
        if (user.isEnabled()) {
            throw new IllegalArgumentException("Account is already verified. Please sign in.");
        }
        otpService.generateAndSend(user.getEmail(), OtpPurpose.EMAIL_VERIFICATION, OtpChannel.EMAIL);
        log.info("Resent registration email verification OTP to {}", user.getEmail());
    }
}
