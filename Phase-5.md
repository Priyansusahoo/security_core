Welcome to the **final chunk** of our journey! Today, we bring every single piece together into a working, secure, production-ready Spring Boot API.

In Chunk 5, we will:
1. Configure the command center of Spring Security: **`SecurityConfig.java`**.
2. Build the Registration & Login endpoints (`AuthController`, `AuthService`, and DTOs).
3. Build protected Bank endpoints (`AccountController`) to test both `ROLE_USER` and `ROLE_ADMIN` permissions.
4. Walk through exact **Postman / `curl` tests** to see stateless security in action!

---

## 🏛️ 1. The Command Center: `SecurityConfig.java`

Create `src/main/java/com/easybyte/bank/config/SecurityConfig.java`. This class configures the `SecurityFilterChain`—telling Spring which URLs are public, which require roles, and where our `JwtAuthenticationFilter` fits inside the request flow.

```java
package com.easybyte.bank.config;

import com.easybyte.bank.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // Allows @PreAuthorize annotations on controller methods if needed later
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1. Disable CSRF (Cross-Site Request Forgery)
            // CSRF protection is required for session/cookie-based apps where browsers auto-attach cookies.
            // Since our REST API is stateless and clients explicitly attach Bearer tokens, CSRF is unnecessary.
            .csrf(AbstractHttpConfigurer::disable)

            // 2. Define URL Authorization Rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints: Anyone can register or log in without a token
                .requestMatchers("/api/auth/**").permitAll()
                
                // Admin endpoints: Only users whose authorities contain ROLE_ADMIN can access
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                
                // Account endpoints: Users with either ROLE_USER or ROLE_ADMIN can access
                .requestMatchers("/api/account/**").hasAnyRole("USER", "ADMIN")
                
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )

            // 3. Stateless Session Management
            // Tells Spring Security NEVER to create or use an HTTP session to store authentication state.
            // Every request MUST be re-authenticated using the JWT.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 4. Register our AuthenticationProvider (configured in ApplicationConfig)
            .authenticationProvider(authenticationProvider)

            // 5. Insert our custom JWT Filter BEFORE Spring's default UsernamePasswordAuthenticationFilter
            // This ensures our filter intercepts the request, validates the token, and populates SecurityContextHolder
            // BEFORE Spring checks whether the request is authenticated.
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

---

## 🔐 2. Authentication API (`/api/auth/**`)

We need three DTOs (Data Transfer Objects), a Service, and a Controller inside the `com.easybyte.bank.auth` package.

### Step 2.1: The DTOs inside `com.easybyte.bank.auth.dto`

#### `RegisterRequest.java`
```java
package com.easybyte.bank.auth.dto;

import com.easybyte.bank.user.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Role role; // Optional: defaults to USER if null
}
```

#### `LoginRequest.java`
```java
package com.easybyte.bank.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
    private String email;
    private String password;
}
```

#### `AuthResponse.java`
```java
package com.easybyte.bank.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    private String token;
    private String message;
}
```

---

### Step 2.2: `AuthService.java` inside `com.easybyte.bank.auth`
This service handles password encryption during registration and coordinates with `AuthenticationManager` during login.

```java
package com.easybyte.bank.auth;

import com.easybyte.bank.auth.dto.AuthResponse;
import com.easybyte.bank.auth.dto.LoginRequest;
import com.easybyte.bank.auth.dto.RegisterRequest;
import com.easybyte.bank.security.JwtService;
import com.easybyte.bank.user.Role;
import com.easybyte.bank.user.User;
import com.easybyte.bank.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        // 1. Check if user already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered!");
        }

        // 2. Build our User entity with BCrypt-hashed password
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // CRITICAL: Never store raw password
                .role(request.getRole() != null ? request.getRole() : Role.USER)
                .build();

        // 3. Save user to PostgreSQL
        userRepository.save(user);

        // 4. Generate JWT token immediately so the user is logged in
        var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .message("User registered successfully!")
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        // 1. Authenticate user using Spring Security's AuthenticationManager.
        // If the email doesn't exist or the password doesn't match the BCrypt hash,
        // this will automatically throw an AuthenticationException (BadCredentialsException)!
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // 2. If execution reaches here, authentication succeeded! Fetch user record.
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        // 3. Generate a fresh JWT token for this session
        var jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .message("Login successful!")
                .build();
    }
}
```

---

### Step 2.3: `AuthController.java` inside `com.easybyte.bank.auth`

```java
package com.easybyte.bank.auth;

import com.easybyte.bank.auth.dto.AuthResponse;
import com.easybyte.bank.auth.dto.LoginRequest;
import com.easybyte.bank.auth.dto.RegisterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
```

---

## 🏦 3. Protected Bank Endpoints (`AccountController.java`)

To prove that our security rules work, create `src/main/java/com/easybyte/bank/account/AccountController.java`.

```java
package com.easybyte.bank.account;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AccountController {

    /**
     * Protected Endpoint for regular users (or admins): /api/account/my-balance
     */
    @GetMapping("/account/my-balance")
    public ResponseEntity<Map<String, Object>> getMyBalance() {
        // We can inspect SecurityContextHolder to see who is calling right now!
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentEmail = authentication.getName();

        return ResponseEntity.ok(Map.of(
                "accountOwner", currentEmail,
                "balance", "$1,500.00",
                "status", "ACTIVE"
        ));
    }

    /**
     * Protected Endpoint strictly for Administrators: /api/admin/all-accounts
     */
    @GetMapping("/admin/all-accounts")
    public ResponseEntity<Map<String, Object>> getAllAccounts() {
        return ResponseEntity.ok(Map.of(
                "totalAccounts", 142,
                "totalVaultFunds", "$2,450,000.00",
                "message", "Welcome, Administrator! You have access to restricted system data."
        ));
    }
}
```

---

## 🧪 4. How to Test Everything Step-by-Step

Start your Spring Boot application right now! Once it boots up, open Postman (or use terminal `curl` commands):

### 🧪 Test 1: Register a regular `USER`
**Request:**
```http
POST http://localhost:8080/api/auth/register
Content-Type: application/json

{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@easybyte.com",
    "password": "Password123!",
    "role": "USER"
}
```
**Expected Response (`200 OK`):**
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huQGVhc3lieXRlLmNvbSIsImlhdCI6MTc4NDU5...",
    "message": "User registered successfully!"
}
```
*(Copy this `token` string! We will use it next).*

---

### 🧪 Test 2: Access a protected route **WITHOUT** a token
Try calling `GET http://localhost:8080/api/account/my-balance` without attaching any header.
**Expected Response:**
* You will get a **`403 Forbidden`** (or `401 Unauthorized`), proving that Spring Security blocked the unauthenticated request before it ever touched your `AccountController`!

---

### 🧪 Test 3: Access `/api/account/my-balance` **WITH** our `USER` token
In Postman, go to the **Headers** tab (or **Authorization -> Bearer Token**) and add:
* Key: `Authorization`
* Value: `Bearer eyJhbGciOiJIUzI1NiJ9...` *(Paste John's token here)*

**Expected Response (`200 OK`):**
```json
{
    "accountOwner": "john@easybyte.com",
    "balance": "$1,500.00",
    "status": "ACTIVE"
}
```
🎉 **Our `JwtAuthenticationFilter` intercepted the request, verified the HMAC-SHA256 signature, populated `SecurityContextHolder`, and allowed John through!**

---

### 🧪 Test 4: Try accessing `/api/admin/all-accounts` using John's (`USER`) token
Keep John's Bearer token attached and try calling `GET http://localhost:8080/api/admin/all-accounts`.
**Expected Response:**
* **`403 Forbidden`**! Because in `SecurityConfig`, we declared `.requestMatchers("/api/admin/**").hasRole("ADMIN")`. Since John has `ROLE_USER`, Spring Security denies him access to admin secrets!

---

### 🧪 Test 5: Register an `ADMIN` and verify Admin Access
Register a second user with `"role": "ADMIN"` (`admin@easybyte.com`), copy their new token, and attach it to `GET http://localhost:8080/api/admin/all-accounts`.
**Expected Response (`200 OK`):**
```json
{
    "totalAccounts": 142,
    "totalVaultFunds": "$2,450,000.00",
    "message": "Welcome, Administrator! You have access to restricted system data."
}
```

---

# 🏁 Congratulations! 🎉
You have just built a complete, production-grade **stateless Spring Security architecture with JWT** from scratch! You mastered:
* Database connection pools and entities implementing **`UserDetails`**.
* Cryptographic signature generation and validation with **`JwtService`**.
* The core authentication engine (`UserDetailsService`, `BCryptPasswordEncoder`, and `DaoAuthenticationProvider`).
* Intercepting requests with **`OncePerRequestFilter`** and setting thread-local state in **`SecurityContextHolder`**.
* Configuring **`SecurityFilterChain`** to enforce public rules, role-based rules, and custom filters.

If you have any questions about anything we covered or if you want to test any specific edge cases next, let me know! How did your tests go?