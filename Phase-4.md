Welcome to **Chunk 4**! This is the most crucial, magical part of stateless authentication: **Interpreting the Bearer Token on incoming HTTP requests using a custom Servlet Filter**.

We will build `JwtAuthenticationFilter.java` inside your `com.easybyte.bank.security` package.

---

### 🧠 1. Core Fundamentals: How Stateless Filters Work

Whenever a request (like `GET /api/account/my-balance`) hits our server, it must pass through Spring Security's **Filter Chain** before reaching our Controller.

```mermaid
graph TD
    Req[Incoming HTTP Request<br/>Header: Authorization: Bearer eyJhbGci...] --> Filter[JwtAuthenticationFilter<br/>OncePerRequestFilter]
    
    Filter -->|1. Extract 'Bearer ' header| CheckHeader{Header starts<br/>with Bearer?}
    CheckHeader -->|No| Next[filterChain.doFilter<br/>Pass to next filter as Anonymous]
    CheckHeader -->|Yes| ExtractJWT[2. Extract JWT String &<br/>jwtService.extractUsername]
    
    ExtractJWT --> CheckContext{User not null &<br/>SecurityContext is null?}
    CheckContext -->|No| Next
    CheckContext -->|Yes| LoadUser[3. userDetailsService.loadUserByUsername]
    
    LoadUser --> ValidateToken{jwtService.isTokenValid?}
    ValidateToken -->|No| Next
    ValidateToken -->|Yes| SetContext[4. Create UsernamePasswordAuthenticationToken<br/>& Save into SecurityContextHolder]
    
    SetContext --> Next
    Next --> Controller[AccountController<br/>Checks if SecurityContext has ROLE_USER -> Success!]
```

#### **Why extend `OncePerRequestFilter`?**
In Java Servlet architecture, standard filters can sometimes be invoked multiple times during a single HTTP request (for example, during internal server forwards or error dispatches). By extending Spring's **`OncePerRequestFilter`**, we guarantee that our JWT validation logic executes **exactly once per request**.

#### **What is `SecurityContextHolder`?**
Because our app is **Stateless** (`SessionCreationPolicy.STATELESS`), Spring Security starts *every single request* assuming the user is **anonymous (unauthenticated)**.
`SecurityContextHolder` is Spring Security's thread-local storage box for the duration of the request. When our `JwtAuthenticationFilter` confirms that the JWT signature is valid, we manually place an `Authentication` token inside `SecurityContextHolder`. From that moment on, for the rest of that HTTP request, Spring Security knows: *"Ah! This request belongs to `john@easybyte.com` who has `ROLE_USER`!"*

---

### 🛠️ 2. Production-Grade Code: `JwtAuthenticationFilter.java`

Create this file inside `src/main/java/com/easybyte/bank/security/JwtAuthenticationFilter.java`.

```java
package com.easybyte.bank.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // 1. Check if the request has the "Authorization" header
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If header is missing or does not start with "Bearer ", pass the request along the filter chain.
        // It will remain unauthenticated, and if the endpoint requires login, Spring Security will reject it later.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Extract the token substring right after "Bearer " (which is 7 characters long: index 7 onwards)
        jwt = authHeader.substring(7);

        // 3. Extract the username (email) from the JWT claims using our JwtService
        userEmail = jwtService.extractUsername(jwt);

        // 4. If we successfully extracted the email AND the user is not already authenticated in the current context:
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            
            // Fetch the user details from PostgreSQL using our UserDetailsService
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // 5. Validate the token against the user details and check expiration
            if (jwtService.isTokenValid(jwt, userDetails)) {
                
                // Create an Authentication token for Spring Security.
                // We pass: principal (userDetails), credentials (null because password verification is done during login), and authorities/roles.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                // Attach details about the request (like user's IP address and browser session details)
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 6. UPDATE SECURITY CONTEXT: This is the exact moment Spring Security recognizes the user as logged in!
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // 7. Always pass the request to the next filter in the chain (e.g., Spring's authorization filters or your Controller)
        filterChain.doFilter(request, response);
    }
}
```

---

### 🔍 Deep Dive: Why Did We Code It This Way?

#### 1. `@Component` & `@RequiredArgsConstructor`
By tagging our filter with `@Component`, Spring detects it and registers it as a Spring Bean. Thanks to `@RequiredArgsConstructor`, Spring automatically injects `JwtService` and `UserDetailsService` into our filter when the application starts.

#### 2. `authHeader.substring(7)`
The HTTP standard for sending Bearer tokens requires the client to format the header exactly like this:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```
The word `Bearer ` is 6 characters plus 1 space = **7 characters**. Taking `.substring(7)` strips away the `"Bearer "` prefix, leaving only the pure JWT token string (`eyJhb...`).

#### 3. `SecurityContextHolder.getContext().getAuthentication() == null`
Why do we check if `getAuthentication()` is null before calling the database?
Because if another filter further up the chain already authenticated this request, we don't want to waste time and database connection resources querying `UserDetailsService` again! We only validate the JWT and query PostgreSQL when the `SecurityContextHolder` is empty (`null`).

#### 4. `UsernamePasswordAuthenticationToken`
Even though we didn't check a password in this filter (we checked a cryptographic signature instead!), `UsernamePasswordAuthenticationToken` is the standard Spring Security implementation of the `Authentication` interface. When we pass `userDetails.getAuthorities()` as the third parameter, Spring automatically flags `authToken.isAuthenticated() = true`.

---

### ✅ Your Action Items for Chunk 4:
1. Create `JwtAuthenticationFilter.java` inside your `com.easybyte.bank.security` package.
2. Verify your imports and make sure your application compiles cleanly with `mvn clean compile`.

Take your time tracing how incoming requests flow through `doFilterInternal()`. Once you understand how this filter populates the `SecurityContextHolder`, let me know and we will proceed to our final piece: **Chunk 5: `SecurityFilterChain` Configuration, Authentication Controllers (`/register`, `/login`), and Testing our Bank Endpoints!**