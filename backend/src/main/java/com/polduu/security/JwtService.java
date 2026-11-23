package com.polduu.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private static final String SESSION_CLAIM = "sid";

    // HS256 requires a key of at least 256 bits
    static final int MIN_SECRET_BYTES = 32;

    private final SecretKey signingKey;
    private final long jwtExpirationMs;

    // Builds and validates the key at startup, so a bad secret stops the app instead of failing per request
    public JwtService(@Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration:900000}") long jwtExpirationMs) {
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(
                    "jwt.secret must be at least " + MIN_SECRET_BYTES + " bytes, got " + keyBytes.length);
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public record AccessToken(UUID userId, UUID sessionId) {}

    // userId is the subject; sessionId ties the token to a refresh-token session so closing it invalidates the token
    public String generateToken(UUID userId, UUID sessionId) {
        return Jwts.builder()
                .subject(userId.toString())
                .claim(SESSION_CLAIM, sessionId.toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(signingKey)
                .compact();
    }

    // Verifies the signature and expiry; tokens without user or session are rejected
    public AccessToken parseAccessToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        String subject = claims.getSubject();
        String session = claims.get(SESSION_CLAIM, String.class);
        if (subject == null) throw new JwtException("Missing subject");
        if (session == null) throw new JwtException("Missing session");
        return new AccessToken(UUID.fromString(subject), UUID.fromString(session));
    }

    public long getJwtExpirationTime() {
        return jwtExpirationMs / 1000; // Convert milliseconds to seconds
    }
}