package com.polduu.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.JwtException;

class JwtServiceTest {

    private static final String SECRET = "test-only-secret-key-at-least-32-bytes-long";
    private static final long EXPIRATION_MS = 900_000;

    @Test
    void generateToken_canBeReadBack() {
        JwtService jwtService = new JwtService(SECRET, EXPIRATION_MS);
        UUID userId = UUID.randomUUID();

        String token = jwtService.generateToken(userId);

        assertThat(jwtService.extractUserId(token)).isEqualTo(userId);
    }

    @Test
    void extractUserId_withTokenSignedByAnotherKey_throws() {
        String foreignToken = new JwtService("another-secret-key-that-is-at-least-32-bytes", EXPIRATION_MS)
                .generateToken(UUID.randomUUID());

        assertThatThrownBy(() -> new JwtService(SECRET, EXPIRATION_MS).extractUserId(foreignToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void extractUserId_withExpiredToken_throws() {
        JwtService expiredService = new JwtService(SECRET, -1_000);
        String token = expiredService.generateToken(UUID.randomUUID());

        assertThatThrownBy(() -> expiredService.extractUserId(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void constructor_withSecretShorterThan32Bytes_failsFast() {
        assertThatThrownBy(() -> new JwtService("a".repeat(31), EXPIRATION_MS))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 32 bytes");
    }

    @Test
    void constructor_withEmptySecret_failsFast() {
        assertThatThrownBy(() -> new JwtService("", EXPIRATION_MS))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getJwtExpirationTime_returnsSeconds() {
        assertThat(new JwtService(SECRET, EXPIRATION_MS).getJwtExpirationTime()).isEqualTo(900);
    }
}
