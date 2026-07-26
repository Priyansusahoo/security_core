Welcome to **Chunk 2**! Now that our database entities are set up, we are diving into the heart of stateless authentication: **JSON Web Tokens (JWT) & Cryptography**.

We will build the **`JwtService`** class inside our `com.easybyte.bank.security` package.

---

### 🧠 1. Core Fundamentals: Anatomy of a JWT & Why Cryptography Matters

A JWT is a compact, URL-safe string composed of three parts separated by periods (`.`):
```text
xxxxx.yyyyy.zzzzz
(Header).(Payload/Claims).(Signature)
```

1. **Header (`xxxxx`)**: Contains metadata, usually the algorithm used (`HS256` or `RS256`) and token type (`JWT`).
2. **Payload / Claims (`yyyyy`)**: Contains data about the user (called **Claims**):
   * `sub` (**Subject**): The unique identifier of the user (in our case, the user's `email`).
   * `iat` (**Issued At**): Timestamp indicating when the token was generated.
   * `exp` (**Expiration**): Timestamp after which the token becomes invalid.
   * *Custom Claims*: We can attach extra information like `role` or `userId`.
3. **Signature (`zzzzz`)**: The most critical part. It is created by taking `Base64Url(Header) + "." + Base64Url(Payload)` and hashing it along with a secret key using `HMAC-SHA256`.

#### ⚠️ Critical Security Rule: Why tampering is impossible
Because the **Signature** is generated using our server's secret key, if an attacker intercepts a token and modifies the payload (for example, changing `role: USER` to `role: ADMIN`), the signature calculation on our server will mismatch during verification, and our app will reject the token immediately!

---

### ⚙️ 2. Configuration (`application.yml`) for JWT Secrets & Expiration

**Never hardcode your secret keys or expiration times in Java code.** Furthermore, since we use `HMAC-SHA256` (`HS256`), the `jjwt` library requires a secret key that is **at least 256 bits (32 bytes) long**; otherwise, it will throw a cryptographic exception!

Add the following under your `src/main/resources/application.yml` file:

```yaml
application:
  security:
    jwt:
      # A 256-bit (32-byte) Base64 encoded secret key. 
      # In true production, load this via Environment Variable: ${JWT_SECRET_KEY}
      secret-key: 404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
      # Token expiration in milliseconds: 86400000 ms = 24 hours
      expiration: 86400000
```

---

### 🛠️ 3. Production-Grade Code: `JwtService.java`

Create this file inside `src/main/java/com/easybyte/bank/security/JwtService.java`.

*(Note: We use modern `jjwt` **0.12.x** APIs. Older tutorials often use deprecated methods like `parseClaimsJws()` or `setSigningKey()`, which are not type-safe and have been removed/deprecated in recent `jjwt` releases).*

```java
package com.easybyte.bank.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    // =========================================================================
    // 1. TOKEN EXTRACTION METHODS
    // =========================================================================

    /**
     * Extracts the username (Subject claim) from the token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic helper method to extract any specific claim using a Claims Resolver function.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // =========================================================================
    // 2. TOKEN GENERATION METHODS
    // =========================================================================

    /**
     * Generates a token without any extra custom claims.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a token with extra custom claims (e.g., custom user roles or IDs) and expiration.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignInKey()) // Uses HMAC-SHA256 automatically based on key size
                .compact();
    }

    // =========================================================================
    // 3. TOKEN VALIDATION METHODS
    // =========================================================================

    /**
     * Validates that the token belongs to the given UserDetails and is not expired.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Checks if the current timestamp is after the token's expiration timestamp.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // =========================================================================
    // 4. LOW-LEVEL CRYPTOGRAPHIC ENGINE
    // =========================================================================

    /**
     * Parses the JWT string, verifies the cryptographic signature, and returns the payload (Claims).
     * If the token is tampered with or expired, this will throw a JwtException (e.g., ExpiredJwtException).
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignInKey()) // Validates the digital signature against our SecretKey
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Converts our Base64-encoded string key into a cryptographic SecretKey object.
     */
    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
```

---

### 🔍 Deep Dive: How the Cryptographic Engine Works

Let’s trace the two most crucial low-level methods:

#### 1. `getSignInKey()`
```java
byte[] keyBytes = Decoders.BASE64.decode(secretKey);
return Keys.hmacShaKeyFor(keyBytes);
```
* **Why decode Base64?** Our secret string in `application.yml` (`404E63...`) is formatted in Hex/Base64 for readability. `Decoders.BASE64.decode` converts it into raw binary bytes (`byte[]`).
* **`Keys.hmacShaKeyFor(keyBytes)`**: This `jjwt` utility inspects the byte length of our key and generates a Java `SecretKey` object optimized for the exact HMAC algorithm (`HS256`).

#### 2. `extractAllClaims(String token)`
```java
Jwts.parser()
    .verifyWith(getSignInKey())
    .build()
    .parseSignedClaims(token)
    .getPayload();
```
* When someone sends a token, `parseSignedClaims(token)` recalculates what the signature *should* be using `verifyWith(getSignInKey())`.
* If the incoming token's signature does not match the recalculated signature exactly, or if the `exp` claim has passed, `jjwt` immediately rejects it by throwing a runtime exception (`SignatureException` or `ExpiredJwtException`).

---

### ✅ Your Action Items for Chunk 2:
1. Add the `application.security.jwt` block to your `application.yml` (or `application.properties`).
2. Create `JwtService.java` inside `src/main/java/com/easybyte/bank/security/`.

Once you have added this class and digested how the cryptography and token generation work, let me know when you are ready to proceed with **Chunk 3: Spring Security Core Architecture (`UserDetailsService` & `PasswordEncoder`)!**