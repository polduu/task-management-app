package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mapstruct.factory.Mappers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.ResponseActions;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.GitHubAuthRequestDto;
import com.polduu.dto.auth.LinkGitHubRequestDto;
import com.polduu.exception.ConflictException;
import com.polduu.exception.ExternalAccountRejectedException;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.exception.ReauthenticationRequiredException;
import com.polduu.mapper.UserMapper;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;
import com.polduu.security.JwtService;

@ExtendWith(MockitoExtension.class)
class GitHubAuthServiceTest {

    private static final String TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String USER_URL = "https://api.github.com/user";
    private static final String EMAILS_URL = "https://api.github.com/user/emails";
    private static final String GITHUB_ID = "12345";
    private static final String EMAIL = "pol@test.com";
    private static final String PROFILE = """
            {"id":12345,"login":"polduu","name":"Pol","email":"public@test.com"}""";
    private static final String VERIFIED_EMAILS = """
            [{"email":"other@test.com","primary":false,"verified":true},
             {"email":"Pol@Test.com","primary":true,"verified":true}]""";

    @Mock UserRepository userRepository;
    @Mock UserIdentityRepository userIdentityRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtService jwtService;
    @Mock RefreshTokenService refreshTokenService;
    @Spy
    private UserMapper userMapper = Mappers.getMapper(UserMapper.class);

    private UserService userService;
    private AccountLinkingService accountLinkingService;

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final GitHubAuthRequestDto request = new GitHubAuthRequestDto("code");

    private final LinkGitHubRequestDto linkRequest = new LinkGitHubRequestDto("code", "secret");

    private MockRestServiceServer github;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        github = MockRestServiceServer.bindTo(builder).build();
        GitHubClient client = new GitHubClient(builder.build(), "client-id", "client-secret");
        userService = new UserService(userRepository, passwordEncoder, jwtService, refreshTokenService, userMapper,
                null, userIdentityRepository, client, TransactionOperations.withoutTransaction());
        accountLinkingService = new AccountLinkingService(userRepository, userIdentityRepository, passwordEncoder,
                refreshTokenService, null, client, TransactionOperations.withoutTransaction());
    }

    // Login and sign up

    @Test
    void githubLogin_withNewUser_createsAccountWithThePrimaryVerifiedEmail() {
        givenAccessToken();
        givenProfile();
        givenEmails(VERIFIED_EMAILS);
        givenNoGitHubAccount();
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            saved.setId(userId);
            return saved;
        });
        givenSession();

        AuthResponseDto response = userService.githubLogin(request);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo(EMAIL);
        assertThat(captor.getValue().getPasswordHash()).isNull();
        UserIdentity identity = savedIdentity();
        assertThat(identity.getUser()).isSameAs(captor.getValue());
        assertThat(identity.getProvider()).isEqualTo(AuthProvider.GITHUB);
        assertThat(identity.getProviderId()).isEqualTo(GITHUB_ID);
        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        github.verify();
    }

    @Test
    void githubLogin_withExistingIdentity_logsInWithoutCreatingAnother() {
        givenAccessToken();
        givenProfile();
        givenGitHubAccountOf(user(userId));
        givenSession();

        AuthResponseDto response = userService.githubLogin(request);

        assertThat(response.user().id()).isEqualTo(userId);
        verify(userRepository, never()).save(any());
        verify(userIdentityRepository, never()).save(any());
        github.verify();
    }

    @Test
    void githubLogin_whenEmailBelongsToAnotherAccount_throwsConflict() {
        givenAccessToken();
        givenProfile();
        givenEmails(VERIFIED_EMAILS);
        givenNoGitHubAccount();
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(ConflictException.class);

        verify(userRepository, never()).save(any());
        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void githubLogin_withRejectedCode_throwsInvalidCredentials() {
        expect(HttpMethod.POST, TOKEN_URL).andRespond(withSuccess(
                "{\"error\":\"bad_verification_code\"}", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void githubLogin_withoutVerifiedPrimaryEmail_throwsInvalidCredentials() {
        givenAccessToken();
        givenProfile();
        givenEmails("[{\"email\":\"pol@test.com\",\"primary\":true,\"verified\":false}]");

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void githubLogin_whenGitHubFails_propagatesRestClientException() {
        expect(HttpMethod.POST, TOKEN_URL).andRespond(withServerError());

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(RestClientException.class);
    }

    // Account linking

    @Test
    void linkGitHubAccount_addsIdentityWithoutRequiringTheSameEmail() {
        User local = userWithPassword();
        givenAccessToken();
        givenProfile();
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        givenNoGitHubAccount();

        accountLinkingService.linkGitHubAccount(userId, sessionId, linkRequest);

        UserIdentity identity = savedIdentity();
        assertThat(identity.getUser()).isSameAs(local);
        assertThat(identity.getProvider()).isEqualTo(AuthProvider.GITHUB);
        assertThat(identity.getProviderId()).isEqualTo(GITHUB_ID);
        github.verify();
    }

    @Test
    void linkGitHubAccount_whenLinkedToAnotherUser_throwsConflict() {
        givenAccessToken();
        givenProfile();
        User local = userWithPassword();
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        givenGitHubAccountOf(user(UUID.randomUUID()));

        assertThatThrownBy(() -> accountLinkingService.linkGitHubAccount(userId, sessionId, linkRequest))
                .isInstanceOf(ConflictException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    @Test
    void linkGitHubAccount_whenUserAlreadyHasGitHub_throwsConflict() {
        givenAccessToken();
        givenProfile();
        User local = userWithPassword();
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        givenNoGitHubAccount();
        when(userIdentityRepository.existsByUserIdAndProvider(userId, AuthProvider.GITHUB)).thenReturn(true);

        assertThatThrownBy(() -> accountLinkingService.linkGitHubAccount(userId, sessionId, linkRequest))
                .isInstanceOf(ConflictException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    @Test
    void linkGitHubAccount_withWrongPassword_neverCallsGitHub() {
        User local = user(userId);
        local.setPasswordHash("hash");
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));

        assertThatThrownBy(() -> accountLinkingService.linkGitHubAccount(userId, sessionId, linkRequest))
                .isInstanceOf(ReauthenticationRequiredException.class);

        github.verify();
        verify(userIdentityRepository, never()).save(any());
    }

    @Test
    void linkGitHubAccount_withRejectedCode_isNotReportedAsAnExpiredSession() {
        User local = userWithPassword();
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        expect(HttpMethod.POST, TOKEN_URL).andRespond(withSuccess(
                "{\"error\":\"bad_verification_code\"}", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> accountLinkingService.linkGitHubAccount(userId, sessionId, linkRequest))
                .isInstanceOf(ExternalAccountRejectedException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    // GitHub errors

    @Test
    void githubLogin_whenHitBySecondaryRateLimit_propagatesRestClientException() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.RETRY_AFTER, "60");
        givenAccessToken();
        expect(HttpMethod.GET, USER_URL).andRespond(withStatus(HttpStatus.FORBIDDEN).headers(headers));

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(RestClientException.class);
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403, 404})
    void githubLogin_whenGitHubRefusesTheToken_throwsInvalidCredentials(int status) {
        givenAccessToken();
        expect(HttpMethod.GET, USER_URL).andRespond(withStatus(HttpStatusCode.valueOf(status)));

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void githubLogin_whenRateLimited_propagatesRestClientException() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-RateLimit-Remaining", "0");
        givenAccessToken();
        expect(HttpMethod.GET, USER_URL).andRespond(withStatus(HttpStatus.FORBIDDEN).headers(headers));

        assertThatThrownBy(() -> userService.githubLogin(request))
                .isInstanceOf(RestClientException.class);
    }

    // Helpers

    private ResponseActions expect(HttpMethod httpMethod, String url) {
        return github.expect(requestTo(url)).andExpect(method(httpMethod));
    }

    private void givenAccessToken() {
        expect(HttpMethod.POST, TOKEN_URL).andRespond(withSuccess(
                "{\"access_token\":\"gh-token\"}", MediaType.APPLICATION_JSON));
    }

    private void givenProfile() {
        expect(HttpMethod.GET, USER_URL)
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer gh-token"))
                .andRespond(withSuccess(PROFILE, MediaType.APPLICATION_JSON));
    }

    private void givenEmails(String json) {
        expect(HttpMethod.GET, EMAILS_URL).andRespond(withSuccess(json, MediaType.APPLICATION_JSON));
    }

    private void givenNoGitHubAccount() {
        when(userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, GITHUB_ID))
                .thenReturn(Optional.empty());
    }

    private void givenGitHubAccountOf(User owner) {
        UserIdentity identity = new UserIdentity();
        identity.setUser(owner);
        identity.setProvider(AuthProvider.GITHUB);
        identity.setProviderId(GITHUB_ID);
        when(userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, GITHUB_ID))
                .thenReturn(Optional.of(identity));
    }

    private void givenSession() {
        when(refreshTokenService.startSession(any(User.class)))
                .thenReturn(new RefreshTokenService.Session(sessionId, "refresh"));
        when(jwtService.generateToken(userId, sessionId)).thenReturn("access");
    }

    private UserIdentity savedIdentity() {
        ArgumentCaptor<UserIdentity> captor = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository).save(captor.capture());
        return captor.getValue();
    }

    private User userWithPassword() {
        User user = user(userId);
        user.setPasswordHash("hash");
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        return user;
    }

    private static User user(UUID id) {
        return User.builder().id(id).username("pol").email("local@test.com").fullName("Pol").build();
    }
}
