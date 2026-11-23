package com.polduu.service;

import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.model.RefreshToken;
import com.polduu.model.User;
import com.polduu.repository.RefreshTokenRepository;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/**
 * Refresh tokens grouped in sessions (families). Only SHA-256 hashes are stored. Each refresh
 * rotates the token; presenting an already used token revokes the whole session, except within a
 * short grace period that tolerates two tabs refreshing at the same time.
 */
@Slf4j
@Service
public class RefreshTokenService {

    static final int MAX_SESSIONS_PER_USER = 5;
    // A used token presented again within this window is treated as a concurrent refresh, not theft
    static final Duration REUSE_GRACE_PERIOD = Duration.ofSeconds(10);
    // Used tokens are kept this long to detect reuse, then purged
    static final Duration USED_TOKEN_RETENTION = Duration.ofDays(1);
    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final Clock clock;
    private final Duration idleTimeout;
    private final Duration maxSessionAge;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, Clock clock,
            @Value("${jwt.refresh-expiration:7d}") Duration idleTimeout,
            @Value("${jwt.refresh-max-session-age:30d}") Duration maxSessionAge) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.clock = clock;
        this.idleTimeout = idleTimeout;
        this.maxSessionAge = maxSessionAge;
    }

    public record Rotation(User user, String refreshToken) {}

    // New session on login or register; closes the least recently used ones beyond the limit
    @Transactional
    public String startSession(User user) {
        Instant now = clock.instant();
        List<RefreshToken> active = refreshTokenRepository.findActiveSessionTokens(user.getId(), now);
        int excess = active.size() - (MAX_SESSIONS_PER_USER - 1);
        for (int i = 0; i < excess; i++) {
            refreshTokenRepository.revokeFamily(active.get(i).getFamilyId(), now);
        }
        return issue(user, UUID.randomUUID(), now.plus(maxSessionAge), now);
    }

    // noRollbackFor: revoking a session on reuse must be saved even though the request fails
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public Rotation rotate(String rawToken) {
        Instant now = clock.instant();
        RefreshToken current = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(RefreshTokenService::invalid);

        if (current.getRevokedAt() != null) {
            throw invalid();
        }
        if (current.getUsedAt() != null) {
            if (current.getUsedAt().plus(REUSE_GRACE_PERIOD).isAfter(now)) {
                throw invalid();
            }
            log.warn("Refresh token reuse detected; revoking session {} of user {}",
                    current.getFamilyId(), current.getUser().getId());
            refreshTokenRepository.revokeFamily(current.getFamilyId(), now);
            throw invalid();
        }
        // expiresAt is never later than the session's absolute expiry
        if (!current.getExpiresAt().isAfter(now)) {
            throw invalid();
        }
        if (refreshTokenRepository.markUsed(current.getId(), now) == 0) {
            // Another request exchanged this token a moment ago: reject without revoking
            throw invalid();
        }

        User user = current.getUser();
        return new Rotation(user, issue(user, current.getFamilyId(), current.getFamilyExpiresAt(), now));
    }

    // Logout: closes only the session the token belongs to
    @Transactional
    public void endSession(String rawToken) {
        refreshTokenRepository.findByTokenHash(hash(rawToken))
                .ifPresent(token -> refreshTokenRepository.revokeFamily(token.getFamilyId(), clock.instant()));
    }

    @Transactional
    public void endAllSessions(UUID userId) {
        refreshTokenRepository.revokeAllForUser(userId, clock.instant());
    }

    @Scheduled(cron = "${jwt.refresh-cleanup-cron:0 0 3 * * *}")
    @Transactional
    public void purgeStaleTokens() {
        Instant now = clock.instant();
        int deleted = refreshTokenRepository.deleteStale(now, now.minus(USED_TOKEN_RETENTION));
        log.info("Purged {} stale refresh tokens", deleted);
    }

    private String issue(User user, UUID familyId, Instant familyExpiresAt, Instant now) {
        String rawToken = newRawToken();
        Instant idleExpiry = now.plus(idleTimeout);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(hash(rawToken));
        token.setFamilyId(familyId);
        token.setUser(user);
        token.setCreatedAt(now);
        token.setFamilyExpiresAt(familyExpiresAt);
        token.setExpiresAt(idleExpiry.isBefore(familyExpiresAt) ? idleExpiry : familyExpiresAt);
        refreshTokenRepository.save(token);
        return rawToken;
    }

    private String newRawToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // SHA-256 is enough here: tokens are long random values, and lookups need a deterministic hash
    static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static InvalidRefreshTokenException invalid() {
        return new InvalidRefreshTokenException("Invalid refresh token");
    }
}
