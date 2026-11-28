package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.polduu.TestcontainersConfiguration;
import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.GitHubAuthRequestDto;
import com.polduu.dto.auth.LinkGitHubRequestDto;
import com.polduu.dto.auth.LinkedAccountsResponseDto;
import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.exception.ReauthenticationRequiredException;
import com.polduu.model.AuthProvider;
import com.polduu.security.JwtService;

/**
 * GitHub login, linking and unlinking with real transactions. Not @Transactional on purpose:
 * it would hide lazy loading outside the short transactions used around GitHub calls.
 */
@SpringBootTest(properties = TestcontainersConfiguration.PROPERTIES)
@Import(TestcontainersConfiguration.class)
class AccountLinkingIntegrationTest {

    @Autowired UserService userService;
    @Autowired AccountLinkingService accountLinkingService;
    @Autowired JwtService jwtService;
    @Autowired JdbcTemplate jdbcTemplate;
    @MockitoBean GitHubClient gitHubClient;

    @BeforeEach
    void setUp() {
        jdbcTemplate.execute("delete from refresh_tokens");
        jdbcTemplate.execute("delete from user_identities");
        jdbcTemplate.execute("delete from users");
        when(gitHubClient.exchangeCode("code")).thenReturn("token");
        when(gitHubClient.fetchProfile("token")).thenReturn(new GitHubClient.Profile("99", "Pol"));
        when(gitHubClient.fetchPrimaryVerifiedEmail("token")).thenReturn("gh@test.com");
    }

    @Test
    void githubLogin_createsTheAccountOnceAndReusesIt() {
        AuthResponseDto first = userService.githubLogin(new GitHubAuthRequestDto("code"));
        AuthResponseDto second = userService.githubLogin(new GitHubAuthRequestDto("code"));

        assertThat(second.user()).isEqualTo(first.user());
        assertThat(identities()).isEqualTo(1);
    }

    @Test
    void passwordAccount_canLinkAndUnlinkWithItsPassword() {
        AuthResponseDto registered = userService.createUser(
                new UserRegisterRequestDto("pol", "pol@test.com", "secret123", "Pol"));
        UUID userId = registered.user().id();
        UUID sessionId = sessionOf(registered);

        accountLinkingService.linkGitHubAccount(userId, sessionId, new LinkGitHubRequestDto("code", "secret123"));
        assertThat(identities()).isEqualTo(1);
        assertThat(accountLinkingService.getLinkedAccounts(userId))
                .isEqualTo(new LinkedAccountsResponseDto(List.of(AuthProvider.GITHUB), true));

        accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, "secret123");
        assertThat(identities()).isZero();
    }

    @Test
    void socialAccount_needsALoginFromTheLastFiveMinutes() {
        AuthResponseDto login = userService.githubLogin(new GitHubAuthRequestDto("code"));
        UUID userId = login.user().id();

        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, UUID.randomUUID(), AuthProvider.GITHUB, null))
                .isInstanceOf(ReauthenticationRequiredException.class);
        // Passes reauthentication, then is refused because it is the only way in
        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionOf(login), AuthProvider.GITHUB, null))
                .hasMessage("Cannot unlink the only sign-in method");

        jdbcTemplate.execute("update refresh_tokens set session_started_at = session_started_at - interval '6 minutes'");
        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionOf(login), AuthProvider.GITHUB, null))
                .isInstanceOf(ReauthenticationRequiredException.class);
    }

    private UUID sessionOf(AuthResponseDto response) {
        return jwtService.parseAccessToken(response.accessToken()).sessionId();
    }

    private int identities() {
        return jdbcTemplate.queryForObject("select count(*) from user_identities", Integer.class);
    }
}
