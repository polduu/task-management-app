package com.polduu;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Postgres for @SpringBootTest classes. Use it together with
 * {@code @SpringBootTest(properties = TestcontainersConfiguration.PROPERTIES)} so every class shares
 * one cached Spring context and one container.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    public static final String PROPERTIES = "jwt.secret=test-only-secret-key-at-least-32-bytes-long";

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgres() {
        return new PostgreSQLContainer("postgres:16");
    }
}
