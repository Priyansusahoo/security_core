package com.sc.security_core.config;

import com.sc.security_core.security.GatewayHeaderFilter;
import com.sc.security_core.security.JwtAuthenticationFilter;
import com.sc.security_core.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfiguration {

    private final AuthenticationProvider authenticationProvider;
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final GatewayHeaderFilter gatewayHeaderFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	
        http.csrf(AbstractHttpConfigurer :: disable)
        
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/v1/api/auth/**", "/error").permitAll()
                        .requestMatchers("/v1/api/admin/**").hasRole(String.valueOf(Role.ADMIN))
                        .requestMatchers("/v1/api/account/**").hasAnyRole(String.valueOf(Role.USER), String.valueOf(Role.ADMIN))
                        .requestMatchers(
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-resources",
                                "/swagger-resources/**",
                                "/configuration/ui",
                                "/configuration/security",
                                "/swagger-ui/**",
                                "/webjars/**",
                                "/swagger-ui.html"
                        ).permitAll()
                        
                        .anyRequest().authenticated()
                        
                ).sessionManagement(session -> session.
                		sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        
                ).authenticationProvider(authenticationProvider)
                
                .addFilterBefore(gatewayHeaderFilter, SecurityContextHolderFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
