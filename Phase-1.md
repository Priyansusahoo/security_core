Awesome! Using PostgreSQL is a fantastic choice for production-grade Spring Boot applications.

To ensure you understand every fundamental concept without getting overwhelmed, we will break this entire journey into **5 distinct chunks**. We will cover **Chunk 1 today** in extreme detail.

---

### 🗺️ Our Step-by-Step Roadmap

* **📍 Chunk 1 (We are here): Database Configuration, `UserDetails` Fundamentals, & Domain Entities (`User`, `Role`, `Repository`)**
* **Chunk 2:** Deep Dive into JWT Cryptography & Building a Production-Grade `JwtService` (Claims, Signatures, Expiration)
* **Chunk 3:** Spring Security Architecture Core: `UserDetailsService`, `PasswordEncoder` (`BCrypt`), and `AuthenticationProvider`
* **Chunk 4:** The Heart of Stateless Security: Building the `JwtAuthenticationFilter` (`OncePerRequestFilter`) & `SecurityContextHolder`
* **Chunk 5:** Putting it Together: `SecurityFilterChain` Configuration, Authentication Controllers (`/register`, `/login`), & Testing

---

# 🚀 Chunk 1: Database Configuration & Core Security Domain Design

In this step, we will connect your Spring Boot application to PostgreSQL and build our core `User` entity. But instead of just creating a basic table, we will design it specifically to integrate with **Spring Security**.

---

## 1. PostgreSQL Database Configuration (`application.yml`)

Spring Boot uses **HikariCP** as its default high-performance JDBC connection pool. When building for production, you should configure explicit connection properties, JPA behavior, and dialect details.

If you are using `application.properties`, you can convert this format, or prefer `application.yml` (located in `src/main/resources/application.yml`) for cleaner hierarchical structuring:

```yaml
spring:
  application:
    name: easybyte-bank-api

  # PostgreSQL Datasource Configuration
  datasource:
    url: jdbc:postgresql://localhost:5432/easybyte_bank
    username: postgres
    password: your_secure_password # Update with your local pgAdmin/postgres password
    driver-class-name: org.postgresql.Driver
    
    # Production-Grade HikariCP Connection Pool Settings
    hikari:
      pool-name: EasyByteHikariPool
      maximum-pool-size: 10         # Max connections in pool (tune based on DB capacity)
      minimum-idle: 2               # Minimum idle connections maintained
      connection-timeout: 30000     # 30 seconds max wait time for a connection
      idle-timeout: 600000          # 10 minutes before idle connections are closed
      max-lifetime: 1800000         # 30 minutes max lifetime of a connection

  # JPA & Hibernate Configuration
  jpa:
    # Set to 'validate' or 'none' in true production. 
    # Use 'update' during development so Hibernate automatically creates/updates tables.
    hibernate:
      ddl-auto: update
    show-sql: true                  # Prints SQL queries to console during dev
    properties:
      hibernate:
        format_sql: true            # Formats logged SQL for readability
        dialect: org.hibernate.dialect.PostgreSQLDialect
```

#### **Core Fundamentals: Why these settings matter?**
* **`ddl-auto: update` vs `validate`**: In development, `update` automatically creates or modifies database tables when your Java entities change. In production, using `update` is dangerous; you should use `validate` and manage schema changes using migration tools like **Flyway** or **Liquibase**.
* **HikariCP Pool Sizing**: Opening database connections is expensive. Hikari maintains a ready-to-use pool of connections (`minimum-idle` to `maximum-pool-size`) so APIs respond instantly.

---

## 2. Spring Security Fundamental: What is `UserDetails`?

Before writing our Java `User` class, let's understand how Spring Security handles users.

Spring Security does **not** know what fields your custom database table has (whether you call it `email`, `username`, `phone_number`, or `login_id`). To bridge this gap, Spring Security provides an interface named **`UserDetails`**.

When you implement `UserDetails` on your JPA Entity, you provide Spring Security with standardized methods to inspect the user:
1. `getAuthorities()`: Returns the user's permissions or roles (`ROLE_USER`, `ROLE_ADMIN`).
2. `getUsername()`: Returns the unique identifier Spring uses during login (e.g., email or username).
3. `getPassword()`: Returns the **encrypted (BCrypt hashed)** password stored in PostgreSQL.
4. `isAccountNonExpired()`, `isAccountNonLocked()`, `isCredentialsNonExpired()`, `isEnabled()`: Booleans allowing you to lock accounts, disable users, or expire credentials.

---

## 3. Production-Grade Code for Chunk 1

Let's create the first 3 files in your project.

### File 1: `Role.java` (Enum)
Instead of storing raw strings for user roles, we use a strongly-typed Java Enum.

```java
package com.easybyte.bank.user;

public enum Role {
    USER,
    ADMIN
}
```

---

### File 2: `User.java` (Entity + `UserDetails`)
This class maps to the `_users` table in PostgreSQL (we avoid naming the table `user` because `user` is a reserved SQL keyword in PostgreSQL!).

```java
package com.easybyte.bank.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_users") // 'user' is a reserved keyword in PostgreSQL
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password; // Will store the BCrypt hashed password

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    // =========================================================================
    // Spring Security UserDetails Interface Implementation
    // =========================================================================

    /**
     * Converts our Role enum into a GrantedAuthority object that Spring Security understands.
     * Spring Security checks roles with the prefix "ROLE_" by convention.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    /**
     * We use the email address as the unique login identifier (`username` in Spring terms).
     */
    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Set to true for simplicity; can be dynamic in production
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Set to false if you want to lock users after failed attempts
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true; // Set to false if you require email verification before activating
    }
}
```

#### **Deep Dive: Key Annotations & Logic Explained**
* **`@Enumerated(EnumType.STRING)`**: By default, JPA saves Enums as integers (`0` for `USER`, `1` for `ADMIN`). If you ever add a new role at the top of the enum later, your integer mappings break! Storing them as exact strings (`"USER"`, `"ADMIN"`) is a **critical production best practice**.
* **`new SimpleGrantedAuthority("ROLE_" + role.name())`**: Spring Security's authorization filters (`hasRole("ADMIN")`) expect role strings to begin with the prefix `ROLE_`. Thus, `ADMIN` becomes `ROLE_ADMIN`.
* **`@PrePersist`**: Ensures the `createdAt` timestamp is automatically populated before Hibernate inserts the row into PostgreSQL.

---

### File 3: `UserRepository.java`
Now we create the Spring Data JPA repository. We need a custom query method to fetch users by their unique login identifier (`email`).

```java
package com.easybyte.bank.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Spring Data JPA will automatically generate the SQL query:
     * SELECT * FROM _users WHERE email = ?
     * 
     * We return an Optional<User> because a user might not exist with that email.
     */
    Optional<User> findByEmail(String email);

    /**
     * Checks if a user with the given email already exists (useful during registration).
     */
    boolean existsByEmail(String email);
}
```

---

### ✅ Your Action Items for Chunk 1:
1. Create your database in PostgreSQL (`CREATE DATABASE easybyte_bank;`) using pgAdmin.
2. Update your `application.yml` (or `application.properties`) with your DB username and password.
3. Create the `Role`, `User`, and `UserRepository` classes in your project.
4. Run the Spring Boot application! When it boots up, check pgAdmin—Hibernate should automatically create the `_users` table with exact column types.

Take your time to digest every piece of this configuration. Once you have created these classes or if you have **any questions** about why something is designed this way, let me know and we will move to **Chunk 2: Building the JWT Cryptography Service (`JwtService`)!**


---

Production Best Practice: Package-by-Feature / Domain-Driven Architecture
```
src/main/java/com/easybyte/bank/
 │
 ├── EasybyteBankApplication.java         # Main Spring Boot starter class
 │
 ├── user/                                # Chunk 1: User Domain Core
 │    ├── Role.java                       # Enum (USER, ADMIN)
 │    ├── User.java                       # Entity implementing UserDetails
 │    └── UserRepository.java             # JPA Repository
 │
 ├── security/                            # Chunks 2, 3 & 4: Security Engine & JWT
 │    ├── JwtService.java                 # Chunk 2: Token generation & validation
 │    ├── JwtAuthenticationFilter.java    # Chunk 4: OncePerRequestFilter for Bearer tokens
 │    └── CustomUserDetailsService.java   # Chunk 3: Loads UserDetails from DB
 │
 ├── config/                              # Chunk 3 & 5: Global Configurations
 │    ├── ApplicationConfig.java          # Chunk 3: PasswordEncoder, AuthenticationManager beans
 │    └── SecurityConfig.java             # Chunk 5: SecurityFilterChain, public vs protected routes
 │
 ├── auth/                                # Chunk 5: Authentication API Endpoints
 │    ├── AuthController.java             # REST Controller (/api/auth/register, /api/auth/login)
 │    ├── AuthService.java                # Business logic for login and registration
 │    └── dto/                            # Data Transfer Objects (Requests/Responses)
 │         ├── RegisterRequest.java
 │         ├── LoginRequest.java
 │         └── AuthResponse.java
 │
 └── account/                             # Bonus / Testing: Protected Bank Domain
      ├── Account.java                    # Bank Account Entity
      ├── AccountRepository.java          # Bank Account Repository
      └── AccountController.java          # Secured Controller (/api/account/my-balance)
```