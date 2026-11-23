package com.polduu.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class AppConfig {

    // Injected instead of calling Instant.now() so time-dependent logic can be tested
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
