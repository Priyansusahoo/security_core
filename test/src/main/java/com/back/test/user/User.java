package com.back.test.user;

import com.back.test.utility.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "_users")
@Getter @Setter @AllArgsConstructor @NoArgsConstructor @Builder
public class User extends BaseEntity implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Email
    @Column(unique = true, nullable = false) @NotBlank
    private String email;

    @Column(nullable = false)
    @ToString.Exclude
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false) @Builder.Default
    private Role role = Role.USER;

    @Column(nullable = false) @Builder.Default
    private boolean accountNonLocked = true;

    @Column(nullable = false) @Builder.Default
    private boolean accountNonExpired = true;

    @Column(nullable = false) @Builder.Default
    private boolean credentialsNonExpired = true;

    @Column(nullable = false) @Builder.Default
    private boolean enabled = true;

    @Override @NonNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override @NonNull
    public String getUsername() {
        return this.email;
    }

    @Override @NonNull
    public String getPassword() {
        return this.password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

}
