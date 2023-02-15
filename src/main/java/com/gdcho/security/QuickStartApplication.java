package com.gdcho.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class QuickStartApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext app = SpringApplication.run(QuickStartApplication.class, args);
    }
}
