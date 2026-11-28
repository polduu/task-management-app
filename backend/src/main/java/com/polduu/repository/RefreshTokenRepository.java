package com.polduu.repository;

import com.polduu.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // Any token of a session: they all share its absolute expiry
    Optional<RefreshToken> findFirstByFamilyId(UUID familyId);

    // Revoking a session revokes all its rows, and purged rows no longer exist: either way it is not active
    boolean existsByFamilyIdAndRevokedAtIsNull(UUID familyId);

    // Atomic: when two requests use the same token at once, only one gets 1
    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.usedAt = :now where t.id = :id and t.usedAt is null")
    int markUsed(UUID id, Instant now);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.familyId = :familyId and t.revokedAt is null")
    int revokeFamily(UUID familyId, Instant now);

    @Modifying(flushAutomatically = true)
    @Query("update RefreshToken t set t.revokedAt = :now where t.user.id = :userId and t.revokedAt is null")
    int revokeAllForUser(UUID userId, Instant now);

    // The current token of each live session, least recently refreshed first
    @Query("""
            select t from RefreshToken t
            where t.user.id = :userId and t.usedAt is null and t.revokedAt is null and t.expiresAt > :now
            order by t.createdAt asc""")
    List<RefreshToken> findActiveSessionTokens(UUID userId, Instant now);

    @Modifying
    @Query("""
            delete from RefreshToken t
            where t.expiresAt < :now or t.revokedAt is not null or t.usedAt < :usedBefore""")
    int deleteStale(Instant now, Instant usedBefore);
}
