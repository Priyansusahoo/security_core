package com.sc.security_core.auth;

import com.sc.mfa_core.config.MfaProperties;
import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.mfa_core.dto.MfaVerificationResult;
import com.sc.mfa_core.service.MfaService;
import com.sc.otp_core.domain.OtpChannel;
import com.sc.otp_core.domain.OtpPurpose;
import com.sc.otp_core.exception.OtpException;
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

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

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

    /**
     * Registers a new user account or recovers a previously unverified registration.
     * Prevents credential or role tampering prior to mailbox verification.
     */
    public Map<String, Object> register(RegisterRequest request) {
        validatePassword(request.getPassword());
        String email = normalizeEmail(request.getEmail());
        Optional<User> existingUserOpt = userRepository.findByEmail(email);
        User user;
        if (existingUserOpt.isPresent()) {
            User existingUser = existingUserOpt.get();
            if (existingUser.isEnabled()) {
                throw new IllegalArgumentException("Email is already registered! Please sign in.");
            }
            // Do not mutate credentials or roles before mailbox ownership is proven
            user = existingUser;
            log.info("Re-dispatching verification code for pending registration: {}", email);
        } else {
            user = User.builder()
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .email(email)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(Role.USER) // Enforce default user role for public registrations
                    .enabled(false)
                    .build();
            user = userRepository.save(user);
            log.info("Created new pending registration for {}", email);
        }
        otpService.generateAndSend(user.getEmail(), OtpPurpose.EMAIL_VERIFICATION, OtpChannel.EMAIL);
        log.info("Dispatched registration email verification OTP to {}", user.getEmail());
        return Map.of(
                "message", "Verification code sent to your email. Please verify to complete registration.",
                "email", user.getEmail(),
                "verificationRequired", true
        );
    }

    public LoginResponse login(LoginRequest request) {
        String email = normalizeEmail(request.getEmail());
    	log.info("Attempting to authenticate user with email: {}", email);
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        request.getPassword()
                )
        );
        
        var user = userRepository.findByEmail(email)
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
        String target = normalizeEmail(result.target());
        User user = userRepository.findByEmail(target)
                .orElseThrow(() -> new UsernameNotFoundException("User not found for target: " + target));
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
        String email = normalizeEmail(request.email());
        // Verify candidate OTP against HMAC-SHA256 in OtpService
        otpService.verify(email, OtpPurpose.EMAIL_VERIFICATION, request.code());
        // Activate the user account
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        user.setEnabled(true);
        userRepository.save(user);
        // Mint JWT token
        String jwtToken = jwtService.generateToken(user);
        log.info("User [{}] successfully verified email. Account enabled and JWT issued.", user.getEmail());
        return AuthResponse.builder()
                .token(jwtToken)
                .message("Email verified successfully! Registration complete.")
                .build();
    }
    /**
     * Dispatches a fresh verification OTP for unverified registrations.
     * Implements anti-enumeration (CWE-204) by silently returning if the email does not exist or is already verified.
     */
    public void resendEmailVerification(EmailResendRequest request) {
        String email = normalizeEmail(request.email());
        userRepository.findByEmail(email).ifPresent(user -> {
            if (!user.isEnabled()) {
                try {
                    otpService.generateAndSend(user.getEmail(), OtpPurpose.EMAIL_VERIFICATION, OtpChannel.EMAIL);
                    log.info("Resent registration email verification OTP to {}", user.getEmail());
                } catch (OtpException ex) {
                    log.warn("Email verification OTP was not resent for {}: {}", user.getEmail(), ex.getMessage());
                }
            } else {
                log.debug("Verification resend skipped: account [{}] is already enabled", email);
            }
        });
    }

    /**
     * Initiates a password reset flow by dispatching an OTP.
     * Implements anti-enumeration (CWE-204) by silently returning if the user does not exist.
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        String email = normalizeEmail(request.email());
        userRepository.findByEmail(email).ifPresent(user -> {
            try {
                otpService.generateAndSend(user.getEmail(), OtpPurpose.PASSWORD_RESET, OtpChannel.EMAIL);
                log.info("Dispatched password reset OTP to {}", user.getEmail());
            } catch (OtpException ex) {
                log.warn("Password reset OTP was not dispatched for {}: {}", user.getEmail(), ex.getMessage());
            }
        });
    }

    /**
     * Validates the reset OTP and updates the user's password.
     */
    public void resetPassword(ResetPasswordRequest request) {
        validatePassword(request.newPassword());
        String email = normalizeEmail(request.email());
        // Verify candidate OTP against HMAC-SHA256 in OtpService
        otpService.verify(email, OtpPurpose.PASSWORD_RESET, request.code());
        // Fetch user and update password
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
        user.setPassword(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
        log.info("Password successfully reset for user [{}]", user.getEmail());
    }

    /**
     * normalizeEmail - utility method
     */
    private String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Validates that candidate password conforms to system minimum length requirements.
     */
    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }
    }
}
