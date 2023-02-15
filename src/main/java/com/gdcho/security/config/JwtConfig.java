package com.gdcho.security.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtConfig {

    private String signature = "7EIT2UoFTQOSu3Iy+g3Dwp+R0SbFTfj+avWIQ8hsAQI=";

    private Long ttl = 1000L * 60 * 60 * 24 * 7;
}
