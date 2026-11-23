package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;

import com.polduu.TestcontainersConfiguration;
import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.RefreshTokenRequestDto;
import com.polduu.dto.auth.UserLoginRequestDto;
import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.repository.RefreshTokenRepository;
import com.polduu.repository.UserRepository;

/**
 * Refresh token sessions against a real Postgres: real transactions, row locks and commits.
 * Not @Transactional on purpose, so each service call commits like in production.
 */
@SpringBootTest(properties = TestcontainersConfiguration.PROPERTIES)
@Import(TestcontainersConfiguration.class)
class RefreshTokenSessionIntegrationTest {

    private static final String EMAIL = "pol@test.com";
    private static final String PASSWORD = "secret123";

    @Autowired UserService userService;
    @Autowired RefreshTokenService refreshTokenService;
    @Autowired RefreshTokenRepository refreshTokenRepository;
    @Autowired UserRepository userRepository;
    @Autowired JdbcTemplate jdbcTemplate;

    @BeforeEach
    void cleanDatabase() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void register_storesOnlyTheHashOfTheRefreshToken() {
        String raw = register().refreshToken();

        List<String> storedHashes = jdbcTemplate.queryForList("select token_hash from refresh_tokens", String.class);
        assertThat(storedHashes).containsExactly(RefreshTokenService.hash(raw));
    }

    @Test
    void refresh_rotatesTheToken_andTheNewOneKeepsWorking() {
        String first = register().refreshToken();

        String second = refresh(first).refreshToken();
        String third = refresh(second).refreshToken();

        assertThat(third).isNotIn(first, second);
    }

    // Two tabs: the old token is rejected for a moment, but the session survives
    @Test
    void refresh_withJustUsedToken_isRejectedButTheSessionStaysAlive() {
        String first = register().refreshToken();
        String second = refresh(first).refreshToken();

        assertRejected(first);

        assertThat(refresh(second).refreshToken()).isNotBlank();
    }

    // Stolen token: reused after the grace period, the whole session is revoked.
    // Also proves noRollbackFor: the revocation is committed although the request fails.
    @Test
    void refresh_withTokenReusedAfterGracePeriod_revokesTheWholeSession() {
        String first = register().refreshToken();
        String second = refresh(first).refreshToken();
        backdateUsedAt(first, Instant.now().minusSeconds(60));

        assertRejected(first);

        assertRejected(second);
    }

    @Test
    void login_createsIndependentSessions_andLogoutClosesOnlyItsOwn() {
        String laptop = register().refreshToken();
        String phone = login().refreshToken();

        userService.logoutUser(new RefreshTokenRequestDto(laptop));

        assertRejected(laptop);
        assertThat(refresh(phone).refreshToken()).isNotBlank();
    }

    @Test
    void login_beyondTheLimit_closesTheLeastRecentlyUsedSession() {
        List<String> sessions = new ArrayList<>();
        sessions.add(register().refreshToken());
        for (int i = 1; i <= RefreshTokenService.MAX_SESSIONS_PER_USER; i++) {
            sessions.add(login().refreshToken());
        }

        assertRejected(sessions.get(0));
        for (String session : sessions.subList(1, sessions.size())) {
            assertThat(refresh(session).refreshToken()).isNotBlank();
        }
    }

    @Test
    void logoutAllSessions_closesEverySession() {
        AuthResponseDto registered = register();
        String other = login().refreshToken();

        userService.logoutAllSessions(registered.user().id());

        assertRejected(registered.refreshToken());
        assertRejected(other);
    }

    // Both requests read the token before either commits; the row lock lets only one win
    @Test
    void concurrentRefreshes_withTheSameToken_onlyOneWins_andTheSessionSurvives() throws Exception {
        String token = register().refreshToken();
        int requests = 2;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(requests);
        try {
            List<Future<String>> results = new ArrayList<>();
            for (int i = 0; i < requests; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    try {
                        return refresh(token).refreshToken();
                    } catch (InvalidRefreshTokenException e) {
                        return null;
                    }
                }));
            }
            start.countDown();

            List<String> winners = new ArrayList<>();
            for (Future<String> result : results) {
                String newToken = result.get(30, TimeUnit.SECONDS);
                if (newToken != null) {
                    winners.add(newToken);
                }
            }

            assertThat(winners).hasSize(1);
            assertThat(refresh(winners.get(0)).refreshToken()).isNotBlank();
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void purgeStaleTokens_deletesRevokedAndOldUsedTokens_andKeepsLiveOnes() {
        String first = register().refreshToken();
        String live = refresh(first).refreshToken();
        String closed = login().refreshToken();
        userService.logoutUser(new RefreshTokenRequestDto(closed));
        backdateUsedAt(first, Instant.now().minus(RefreshTokenService.USED_TOKEN_RETENTION).minusSeconds(60));

        refreshTokenService.purgeStaleTokens();

        List<String> remaining = jdbcTemplate.queryForList("select token_hash from refresh_tokens", String.class);
        assertThat(remaining).containsExactly(RefreshTokenService.hash(live));
    }

    /*----------------------------------------------------------------------------- */
    // Helpers

    private AuthResponseDto register() {
        return userService.createUser(new UserRegisterRequestDto("pol", EMAIL, PASSWORD, "Pol"));
    }

    private AuthResponseDto login() {
        return userService.logInUser(new UserLoginRequestDto(EMAIL, PASSWORD));
    }

    private AuthResponseDto refresh(String refreshToken) {
        return userService.refreshToken(new RefreshTokenRequestDto(refreshToken));
    }

    private void assertRejected(String refreshToken) {
        assertThatThrownBy(() -> refresh(refreshToken)).isInstanceOf(InvalidRefreshTokenException.class);
    }

    private void backdateUsedAt(String rawToken, Instant usedAt) {
        int updated = jdbcTemplate.update("update refresh_tokens set used_at = ? where token_hash = ?",
                Timestamp.from(usedAt), RefreshTokenService.hash(rawToken));
        assertThat(updated).isEqualTo(1);
    }
}
