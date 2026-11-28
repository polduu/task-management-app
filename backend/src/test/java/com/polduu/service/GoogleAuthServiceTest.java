package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mapstruct.factory.Mappers;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.GoogleAuthRequestDto;
import com.polduu.exception.ConflictException;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.mapper.UserMapper;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;
import com.polduu.security.JwtService;

@ExtendWith(MockitoExtension.class)
class GoogleAuthServiceTest {

    @Mock UserRepository userRepository;
    @Mock UserIdentityRepository userIdentityRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtService jwtService;
    @Mock RefreshTokenService refreshTokenService;
    @Mock GoogleIdTokenVerifier googleIdTokenVerifier;
    @Spy
    private UserMapper userMapper = Mappers.getMapper(UserMapper.class);

    @InjectMocks UserService userService;

    private static final String ID_TOKEN = "id-token";
    private static final String SUBJECT = "google-sub";
    private static final String EMAIL = "pol@test.com";

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final GoogleAuthRequestDto request = new GoogleAuthRequestDto(ID_TOKEN);

    // Token verification

    static Exception[] verifierFailures() {
        return new Exception[] {
            new IOException("network down"),
            new GeneralSecurityException("bad key"),
            new IllegalArgumentException("not a JWT")
        };
    }

    @ParameterizedTest
    @MethodSource("verifierFailures")
    void googleLogin_whenVerificationFails_throwsInvalidCredentials(Exception failure) throws Exception {
        when(googleIdTokenVerifier.verify(ID_TOKEN)).thenThrow(failure);

        assertThatThrownBy(() -> userService.googleLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void googleLogin_withRejectedToken_throwsInvalidCredentials() throws Exception {
        when(googleIdTokenVerifier.verify(ID_TOKEN)).thenReturn(null);

        assertThatThrownBy(() -> userService.googleLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void googleLogin_withUnverifiedEmail_throwsInvalidCredentials() throws Exception {
        givenToken(payload(EMAIL).setEmailVerified(false));

        assertThatThrownBy(() -> userService.googleLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any());
        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void googleLogin_withoutEmail_throwsInvalidCredentials() throws Exception {
        givenToken(payload(null));

        assertThatThrownBy(() -> userService.googleLogin(request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any());
    }

    // Login and sign up

    @Test
    void googleLogin_withNewUser_createsGoogleAccountWithNormalizedData() throws Exception {
        givenToken(payload("  Pol@Test.com ").set("name", "Jos\u00e9 P\u00e9rez"));
        givenNoGoogleAccount();
        givenSavedUserGetsId();
        givenSession();

        AuthResponseDto response = userService.googleLogin(request);

        User saved = savedUser();
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getUsername()).isEqualTo("jose_perez");
        assertThat(saved.getFullName()).isEqualTo("Jos\u00e9 P\u00e9rez");
        UserIdentity identity = savedIdentity();
        assertThat(identity.getUser()).isSameAs(saved);
        assertThat(identity.getProvider()).isEqualTo(AuthProvider.GOOGLE);
        assertThat(identity.getProviderId()).isEqualTo(SUBJECT);
        assertThat(saved.getPasswordHash()).isNull();
        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
    }

    @Test
    void googleLogin_withoutName_usesDefaults() throws Exception {
        givenToken(payload(EMAIL));
        givenNoGoogleAccount();
        givenSavedUserGetsId();
        givenSession();

        userService.googleLogin(request);

        User saved = savedUser();
        assertThat(saved.getUsername()).isEqualTo("user");
        assertThat(saved.getFullName()).isEqualTo("User");
    }

    @Test
    void googleLogin_withLongNameAndTakenUsername_truncatesAndAddsSuffix() throws Exception {
        givenToken(payload(EMAIL).set("name", "a".repeat(150)));
        givenNoGoogleAccount();
        when(userRepository.existsByUsername("a".repeat(40))).thenReturn(true);
        givenSavedUserGetsId();
        givenSession();

        userService.googleLogin(request);

        User saved = savedUser();
        assertThat(saved.getFullName()).hasSize(100);
        assertThat(saved.getUsername()).matches("a{40}_[0-9a-f]{4}");
    }

    @Test
    void googleLogin_withExistingGoogleUser_logsInWithoutCreatingAnother() throws Exception {
        givenToken(payload("new-address@test.com"));
        givenGoogleAccountOf(user());
        givenSession();

        AuthResponseDto response = userService.googleLogin(request);

        assertThat(response.user().id()).isEqualTo(userId);
        verify(userRepository, never()).save(any());
    }

    @Test
    void googleLogin_whenEmailBelongsToAnotherAccount_throwsConflict() throws Exception {
        givenToken(payload(EMAIL));
        givenNoGoogleAccount();
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> userService.googleLogin(request))
                .isInstanceOf(ConflictException.class);

        verify(userRepository, never()).save(any());
        verify(refreshTokenService, never()).startSession(any());
    }

    // Account linking

    @Test
    void linkGoogleAccount_addsIdentityAndKeepsPassword() throws Exception {
        User local = user();
        local.setPasswordHash("hash");
        givenToken(payload(EMAIL));
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        givenNoGoogleAccount();

        userService.linkGoogleAccount(userId, request);

        UserIdentity identity = savedIdentity();
        assertThat(identity.getUser()).isSameAs(local);
        assertThat(identity.getProvider()).isEqualTo(AuthProvider.GOOGLE);
        assertThat(identity.getProviderId()).isEqualTo(SUBJECT);
        assertThat(local.getPasswordHash()).isEqualTo("hash");
    }

    @Test
    void linkGoogleAccount_withDifferentEmail_linksWithoutChangingTheEmail() throws Exception {
        User local = user();
        givenToken(payload("other@test.com"));
        when(userRepository.findById(userId)).thenReturn(Optional.of(local));
        givenNoGoogleAccount();

        userService.linkGoogleAccount(userId, request);

        assertThat(savedIdentity().getUser()).isSameAs(local);
        assertThat(local.getEmail()).isEqualTo(EMAIL);
    }

    @Test
    void linkGoogleAccount_withUnverifiedEmail_throwsInvalidCredentials() throws Exception {
        givenToken(payload(EMAIL).setEmailVerified(false));

        assertThatThrownBy(() -> userService.linkGoogleAccount(userId, request))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    @Test
    void linkGoogleAccount_whenLinkedToAnotherUser_throwsConflict() throws Exception {
        User other = user();
        other.setId(UUID.randomUUID());
        givenToken(payload(EMAIL));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user()));
        givenGoogleAccountOf(other);

        assertThatThrownBy(() -> userService.linkGoogleAccount(userId, request))
                .isInstanceOf(ConflictException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    @Test
    void linkGoogleAccount_whenUserAlreadyHasGoogle_throwsConflict() throws Exception {
        givenToken(payload(EMAIL));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user()));
        givenNoGoogleAccount();
        when(userIdentityRepository.existsByUserIdAndProvider(userId, AuthProvider.GOOGLE)).thenReturn(true);

        assertThatThrownBy(() -> userService.linkGoogleAccount(userId, request))
                .isInstanceOf(ConflictException.class);

        verify(userIdentityRepository, never()).save(any());
    }

    // Helpers

    private static GoogleIdToken.Payload payload(String email) {
        return new GoogleIdToken.Payload()
                .setSubject(SUBJECT)
                .setEmail(email)
                .setEmailVerified(true);
    }

    private void givenToken(GoogleIdToken.Payload payload) throws Exception {
        GoogleIdToken idToken = mock(GoogleIdToken.class);
        when(idToken.getPayload()).thenReturn(payload);
        when(googleIdTokenVerifier.verify(ID_TOKEN)).thenReturn(idToken);
    }

    private void givenNoGoogleAccount() {
        when(userIdentityRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.empty());
    }

    private void givenGoogleAccountOf(User owner) {
        UserIdentity identity = new UserIdentity();
        identity.setUser(owner);
        identity.setProvider(AuthProvider.GOOGLE);
        identity.setProviderId(SUBJECT);
        when(userIdentityRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, SUBJECT))
                .thenReturn(Optional.of(identity));
    }

    private UserIdentity savedIdentity() {
        ArgumentCaptor<UserIdentity> captor = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository).save(captor.capture());
        return captor.getValue();
    }

    private void givenSavedUserGetsId() {
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            saved.setId(userId);
            return saved;
        });
    }

    private void givenSession() {
        when(refreshTokenService.startSession(any(User.class)))
                .thenReturn(new RefreshTokenService.Session(sessionId, "refresh"));
        when(jwtService.generateToken(userId, sessionId)).thenReturn("access");
    }

    private User savedUser() {
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        return captor.getValue();
    }

    private User user() {
        User user = new User();
        user.setId(userId);
        user.setEmail(EMAIL);
        user.setUsername("pol");
        user.setFullName("Pol");
        return user;
    }
}
