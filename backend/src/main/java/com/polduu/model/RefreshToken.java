package com.polduu.model;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

/**
 * One refresh token of a session. Every refresh marks the current token as used and issues a new
 * one in the same family (session), so a used token presented again reveals a stolen token.
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_refresh_tokens_family_id", columnList = "family_id"),
    @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id")
})
@Getter
@Setter
public class RefreshToken {

    @Id
    @GeneratedValue
    @UuidGenerator
    private UUID id;

    // SHA-256 (hex) of the token; the token itself is only ever sent to the client
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    // Shared by every token of the same session
    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    // Idle expiry of this token, never later than familyExpiresAt
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    // Absolute end of the session, regardless of refreshes
    @Column(name = "family_expires_at", nullable = false)
    private Instant familyExpiresAt;

    // Set when the token is exchanged for a new one
    @Column(name = "used_at")
    private Instant usedAt;

    // Set when the session is closed (logout, reuse detected, session limit)
    @Column(name = "revoked_at")
    private Instant revokedAt;
}
