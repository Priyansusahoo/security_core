package com.sc.security_core.auth;

import com.sc.security_core.auth.dto.AuthResponse;
import com.sc.security_core.auth.dto.LoginRequest;
import com.sc.security_core.auth.dto.RegisterRequest;
import com.sc.security_core.security.JwtService;
import com.sc.security_core.user.Role;
import com.sc.security_core.user.User;
import com.sc.security_core.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

    public AuthResponse login(LoginRequest request) {
    	
    	log.info("Attempting to authenticate user with email: {}", request.getEmail());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        var jwtToken = jwtService.generateToken(user);
        log.info("User {} authenticated successfully. Generating JWT.", user.getEmail());

        return AuthResponse.builder()
                .token(jwtToken)
                .message("Login successful!")
                .build();
    }
}
