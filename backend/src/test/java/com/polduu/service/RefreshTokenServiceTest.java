package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.model.AuthProvider;
import com.polduu.model.RefreshToken;
import com.polduu.model.User;
import com.polduu.repository.RefreshTokenRepository;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-23T12:00:00Z");
    private static final Duration IDLE_TIMEOUT = Duration.ofDays(7);
    private static final Duration MAX_SESSION_AGE = Duration.ofDays(30);
    private static final String RAW_TOKEN = "raw-token";

    @Mock RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenService service;
    private User user;

    @BeforeEach
    void setUp() {
        service = new RefreshTokenService(refreshTokenRepository, Clock.fixed(NOW, ZoneOffset.UTC),
                IDLE_TIMEOUT, MAX_SESSION_AGE);
        user = User.builder().id(UUID.randomUUID()).username("pol").email("pol@test.com")
                .fullName("Pol").authProvider(AuthProvider.LOCAL).build();
    }

    /*----------------------------------------------------------------------------- */
    // startSession

    @Test
    void startSession_storesOnlyTheHashAndSetsBothExpiries() {
        String raw = service.startSession(user);

        RefreshToken saved = captureSaved();
        assertThat(raw).matches("[A-Za-z0-9_-]{43}");
        assertThat(saved.getTokenHash()).isEqualTo(RefreshTokenService.hash(raw)).isNotEqualTo(raw);
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getFamilyId()).isNotNull();
        assertThat(saved.getCreatedAt()).isEqualTo(NOW);
        assertThat(saved.getExpiresAt()).isEqualTo(NOW.plus(IDLE_TIMEOUT));
        assertThat(saved.getFamilyExpiresAt()).isEqualTo(NOW.plus(MAX_SESSION_AGE));
        assertThat(saved.getUsedAt()).isNull();
    }

    @Test
    void startSession_issuesADifferentTokenEachTime() {
        assertThat(service.startSession(user)).isNotEqualTo(service.startSession(user));
    }

    @Test
    void startSession_withFourLiveSessions_revokesNothing() {
        when(refreshTokenRepository.findActiveSessionTokens(user.getId(), NOW)).thenReturn(liveSessions(4));

        service.startSession(user);

        verify(refreshTokenRepository, never()).revokeFamily(any(), any());
    }

    @Test
    void startSession_atTheLimit_revokesTheLeastRecentlyUsedSession() {
        List<RefreshToken> live = liveSessions(RefreshTokenService.MAX_SESSIONS_PER_USER);
        when(refreshTokenRepository.findActiveSessionTokens(user.getId(), NOW)).thenReturn(live);

        service.startSession(user);

        verify(refreshTokenRepository).revokeFamily(live.get(0).getFamilyId(), NOW);
        verify(refreshTokenRepository, times(1)).revokeFamily(any(), any());
    }

    /*----------------------------------------------------------------------------- */
    // rotate

    @Test
    void rotate_withValidToken_marksItUsedAndIssuesANewOneInTheSameSession() {
        RefreshToken current = token();
        stubLookup(current);
        when(refreshTokenRepository.markUsed(current.getId(), NOW)).thenReturn(1);

        RefreshTokenService.Rotation rotation = service.rotate(RAW_TOKEN);

        RefreshToken saved = captureSaved();
        assertThat(rotation.user()).isEqualTo(user);
        assertThat(rotation.refreshToken()).isNotEqualTo(RAW_TOKEN);
        assertThat(saved.getTokenHash()).isEqualTo(RefreshTokenService.hash(rotation.refreshToken()));
        assertThat(saved.getFamilyId()).isEqualTo(current.getFamilyId());
        assertThat(saved.getFamilyExpiresAt()).isEqualTo(current.getFamilyExpiresAt());
        assertThat(saved.getExpiresAt()).isEqualTo(NOW.plus(IDLE_TIMEOUT));
    }

    @Test
    void rotate_nearTheEndOfTheSession_capsExpiryAtTheSessionLimit() {
        RefreshToken current = token();
        current.setFamilyExpiresAt(NOW.plus(Duration.ofDays(2)));
        stubLookup(current);
        when(refreshTokenRepository.markUsed(current.getId(), NOW)).thenReturn(1);

        service.rotate(RAW_TOKEN);

        assertThat(captureSaved().getExpiresAt()).isEqualTo(NOW.plus(Duration.ofDays(2)));
    }

    @Test
    void rotate_withUnknownToken_isRejected() {
        when(refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(RAW_TOKEN))).thenReturn(Optional.empty());

        assertRejected();
    }

    @Test
    void rotate_withRevokedSession_isRejected() {
        RefreshToken current = token();
        current.setRevokedAt(NOW.minusSeconds(60));
        stubLookup(current);

        assertRejected();
        verify(refreshTokenRepository, never()).markUsed(any(), any());
    }

    @Test
    void rotate_withExpiredToken_isRejected() {
        RefreshToken current = token();
        current.setExpiresAt(NOW);
        stubLookup(current);

        assertRejected();
        verify(refreshTokenRepository, never()).markUsed(any(), any());
    }

    // Two tabs refreshing at once: the second one fails, but the session stays alive
    @Test
    void rotate_withTokenUsedWithinGracePeriod_isRejectedWithoutRevoking() {
        RefreshToken current = token();
        current.setUsedAt(NOW.minus(RefreshTokenService.REUSE_GRACE_PERIOD).plusSeconds(1));
        stubLookup(current);

        assertRejected();
        verify(refreshTokenRepository, never()).revokeFamily(any(), any());
    }

    // A used token coming back later means it was stolen: close the whole session
    @Test
    void rotate_withTokenReusedAfterGracePeriod_revokesTheSession() {
        RefreshToken current = token();
        current.setUsedAt(NOW.minus(RefreshTokenService.REUSE_GRACE_PERIOD));
        stubLookup(current);

        assertRejected();
        verify(refreshTokenRepository).revokeFamily(current.getFamilyId(), NOW);
    }

    // The other request marked the token as used between our read and our update
    @Test
    void rotate_losingAConcurrentRefresh_isRejectedWithoutRevoking() {
        RefreshToken current = token();
        stubLookup(current);
        when(refreshTokenRepository.markUsed(current.getId(), NOW)).thenReturn(0);

        assertRejected();
        verify(refreshTokenRepository, never()).revokeFamily(any(), any());
    }

    /*----------------------------------------------------------------------------- */
    // endSession, purgeStaleTokens

    @Test
    void endSession_revokesOnlyTheTokensSession() {
        RefreshToken current = token();
        stubLookup(current);

        service.endSession(RAW_TOKEN);

        verify(refreshTokenRepository).revokeFamily(current.getFamilyId(), NOW);
    }

    @Test
    void endSession_withUnknownToken_doesNothing() {
        when(refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(RAW_TOKEN))).thenReturn(Optional.empty());

        service.endSession(RAW_TOKEN);

        verify(refreshTokenRepository, never()).revokeFamily(any(), any());
    }

    @Test
    void purgeStaleTokens_keepsUsedTokensForTheRetentionPeriod() {
        service.purgeStaleTokens();

        verify(refreshTokenRepository).deleteStale(NOW, NOW.minus(RefreshTokenService.USED_TOKEN_RETENTION));
    }

    @Test
    void hash_isAStableSha256Hex() {
        assertThat(RefreshTokenService.hash("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /*----------------------------------------------------------------------------- */
    // Helpers

    private RefreshToken token() {
        RefreshToken token = new RefreshToken();
        token.setId(UUID.randomUUID());
        token.setTokenHash(RefreshTokenService.hash(RAW_TOKEN));
        token.setFamilyId(UUID.randomUUID());
        token.setUser(user);
        token.setCreatedAt(NOW.minus(Duration.ofHours(1)));
        token.setExpiresAt(NOW.plus(Duration.ofDays(6)));
        token.setFamilyExpiresAt(NOW.plus(Duration.ofDays(20)));
        return token;
    }

    private List<RefreshToken> liveSessions(int count) {
        return IntStream.range(0, count).mapToObj(i -> token()).toList();
    }

    private void stubLookup(RefreshToken token) {
        when(refreshTokenRepository.findByTokenHash(RefreshTokenService.hash(RAW_TOKEN))).thenReturn(Optional.of(token));
    }

    private RefreshToken captureSaved() {
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        return captor.getValue();
    }

    private void assertRejected() {
        assertThatThrownBy(() -> service.rotate(RAW_TOKEN))
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid refresh token");
        verify(refreshTokenRepository, never()).save(any());
    }
}
