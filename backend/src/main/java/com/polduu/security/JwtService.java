package com.polduu.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtService {

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

    // Token generation method with userId as the subject
    public String generateToken(UUID userId) {
        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(signingKey)
                .compact();
    }

    // Extract the UserId (subject) from the token
    public UUID extractUserId(String token) {
        String subject = extractClaim(token, Claims::getSubject);
        if (subject == null) throw new io.jsonwebtoken.JwtException("Missing subject");
        return UUID.fromString(subject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public long getJwtExpirationTime() {
        return jwtExpirationMs / 1000; // Convert milliseconds to seconds
    }
}