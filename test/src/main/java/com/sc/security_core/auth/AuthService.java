package com.sc.security_core.auth;

import com.sc.mfa_core.config.MfaProperties;
import com.sc.mfa_core.dto.MfaChallengeResponse;
import com.sc.mfa_core.dto.MfaResendRequest;
import com.sc.mfa_core.dto.MfaVerificationRequest;
import com.sc.mfa_core.dto.MfaVerificationResult;
import com.sc.mfa_core.service.MfaService;
import com.sc.otp_core.domain.OtpChannel;
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

    public AuthResponse register(RegisterRequest request) {
    	
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered!");
        }
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .build();

        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .message("User registered successfully!")
                .build();
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
}
