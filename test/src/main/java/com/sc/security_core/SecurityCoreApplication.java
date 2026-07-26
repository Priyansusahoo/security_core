package com.sc.security_core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing
@SpringBootApplication
public class SecurityCoreApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityCoreApplication.class, args);
	}

}
