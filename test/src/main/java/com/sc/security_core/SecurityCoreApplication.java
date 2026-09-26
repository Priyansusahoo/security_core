package com.sc.security_core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@EnableJpaAuditing
@SpringBootApplication(scanBasePackages = "com.sc")
@EnableJpaRepositories(basePackages = "com.sc")
@EntityScan(basePackages = "com.sc")
public class SecurityCoreApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityCoreApplication.class, args);
	}

}
