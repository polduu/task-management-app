package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mapstruct.factory.Mappers;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.RefreshTokenRequestDto;
import com.polduu.dto.auth.UserLoginRequestDto;
import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.dto.user.PublicUserResponseDto;
import com.polduu.dto.user.UserPatchRequestDto;
import com.polduu.dto.user.UserResponseDto;
import com.polduu.exception.ConflictException;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.exception.ResourceNotFoundException;
import com.polduu.mapper.UserMapper;
import com.polduu.model.User;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;
import com.polduu.security.JwtService;


@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock UserRepository userRepository;
    @Mock UserIdentityRepository userIdentityRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtService jwtService;
    @Mock RefreshTokenService refreshTokenService;
    @Mock GoogleIdTokenVerifier googleIdTokenVerifier;
    @Spy
    private UserMapper userMapper = Mappers.getMapper(UserMapper.class);

    @InjectMocks UserService userService;

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private static final String EMAIL = "pol@test.com";
    private static final String USERNAME = "pol";
    private static final String FULLNAME = "Pol";
    private static final String PASSWORD = "secret123";
    private static final String HASH = "hashed";

    /*-------------------------------------------------------------------------- */
    // Tests for createUser

    @Test
    void createUser_withNewUser_hashesPasswordAndReturnsTokens() {
        var request = new UserRegisterRequestDto(USERNAME, EMAIL, PASSWORD, FULLNAME);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(false);
        when(passwordEncoder.encode(PASSWORD)).thenReturn(HASH);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User u = invocation.getArgument(0);
            u.setId(userId);
            return u;
        });
        when(refreshTokenService.startSession(any(User.class)))
                .thenReturn(new RefreshTokenService.Session(sessionId, "refresh"));
        when(jwtService.generateToken(userId, sessionId)).thenReturn("access");

        AuthResponseDto response = userService.createUser(request);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getUsername()).isEqualTo(USERNAME);
        assertThat(saved.getFullName()).isEqualTo(FULLNAME);
        assertThat(saved.getPasswordHash()).isEqualTo(HASH);

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        assertThat(response.user().id()).isEqualTo(userId);
        assertThat(response.user().email()).isEqualTo(EMAIL);

        verify(refreshTokenService).startSession(saved);
    }

    @Test
    void createUser_withExistingEmail_throwsConflict() {
        var request = new UserRegisterRequestDto(USERNAME, EMAIL, PASSWORD, FULLNAME);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(request))
                .isInstanceOf(ConflictException.class)
                .hasMessage("Email already exists");

        verify(userRepository, never()).save(any());
        verify(userRepository, never()).existsByUsername(any());
    }

    @Test
    void createUser_withExistingUsername_throwsConflict() {
        var request = new UserRegisterRequestDto(USERNAME, EMAIL, PASSWORD, FULLNAME);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(false);
        when(userRepository.existsByUsername(USERNAME)).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(request))
                .isInstanceOf(ConflictException.class)
                .hasMessage("Username already exists");

        verify(userRepository, never()).save(any());
    }

    @Test
    void createUser_withExistingEmail_issuesNoTokens() {
        var request = new UserRegisterRequestDto(USERNAME, EMAIL, PASSWORD, FULLNAME);
        when(userRepository.existsByEmail(EMAIL)).thenReturn(true);

        assertThatThrownBy(() -> userService.createUser(request))
                .isInstanceOf(ConflictException.class);

        verify(jwtService, never()).generateToken(any(), any());
        verify(refreshTokenService, never()).startSession(any());
    }

    /*----------------------------------------------------------------------------- */
    // Tests for logInUser

    @Test
    void logInUser_withValidCredentials_returnsTokens() {
        User user = buildUser();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, HASH)).thenReturn(true);
        when(refreshTokenService.startSession(user))
                .thenReturn(new RefreshTokenService.Session(sessionId, "refresh"));
        when(jwtService.generateToken(userId, sessionId)).thenReturn("access");

        AuthResponseDto response = userService.logInUser(new UserLoginRequestDto(EMAIL, PASSWORD));

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        assertThat(response.user().id()).isEqualTo(userId);
        assertThat(response.user().email()).isEqualTo(EMAIL);
    }

    @Test
    void logInUser_withUnknownEmail_throwsInvalidRequestException() {
        when(userRepository.findByEmail("ghost@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.logInUser(new UserLoginRequestDto("ghost@test.com", PASSWORD)))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any(), any());
        verify(refreshTokenService, never()).startSession(any());
    }

    // Timing: an unknown email must cost the same password check as a wrong password
    @Test
    void logInUser_withUnknownEmail_stillChecksPasswordAgainstARealHash() {
        PasswordEncoder realEncoder = spy(new BCryptPasswordEncoder(4));
        UserService service = new UserService(userRepository, realEncoder, jwtService, refreshTokenService, userMapper, googleIdTokenVerifier, userIdentityRepository);
        when(userRepository.findByEmail("ghost@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.logInUser(new UserLoginRequestDto("ghost@test.com", PASSWORD)))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(realEncoder).matches(eq(PASSWORD), startsWith("$2a$"));
    }

    // Accounts without a password (future OAuth users) must not be able to log in with one
    @Test
    void logInUser_withUserWithoutPassword_failsAfterCheckingAgainstARealHash() {
        PasswordEncoder realEncoder = spy(new BCryptPasswordEncoder(4));
        UserService service = new UserService(userRepository, realEncoder, jwtService, refreshTokenService, userMapper, googleIdTokenVerifier, userIdentityRepository);
        User oauthUser = buildUser();
        oauthUser.setPasswordHash(null);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(oauthUser));

        assertThatThrownBy(() -> service.logInUser(new UserLoginRequestDto(EMAIL, PASSWORD)))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(realEncoder).matches(eq(PASSWORD), startsWith("$2a$"));
        verify(refreshTokenService, never()).startSession(any());
    }

    @Test
    void logInUser_withWrongPassword_throwsInvalidRequestException() {
        User user = buildUser();
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", HASH)).thenReturn(false);

        assertThatThrownBy(() -> userService.logInUser(new UserLoginRequestDto(EMAIL, "wrong")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any(), any());
        verify(refreshTokenService, never()).startSession(any());
    }

    /*----------------------------------------------------------------------------- */
    // Tests for refreshToken

    @Test
    void refreshToken_withValidToken_returnsNewAccessAndRotatedRefreshToken() {
        User user = buildUser();
        when(refreshTokenService.rotate("old-token"))
                .thenReturn(new RefreshTokenService.Rotation(user, sessionId, "new-token"));
        when(jwtService.generateToken(userId, sessionId)).thenReturn("new-access");

        AuthResponseDto response = userService.refreshToken(new RefreshTokenRequestDto("old-token"));

        assertThat(response.accessToken()).isEqualTo("new-access");
        assertThat(response.refreshToken()).isEqualTo("new-token");
        assertThat(response.user().id()).isEqualTo(userId);
        assertThat(response.user().email()).isEqualTo(EMAIL);
    }

    @Test
    void refreshToken_withRejectedToken_propagatesExceptionAndIssuesNothing() {
        when(refreshTokenService.rotate("rejected"))
                .thenThrow(new InvalidRefreshTokenException("Invalid refresh token"));

        assertThatThrownBy(() -> userService.refreshToken(new RefreshTokenRequestDto("rejected")))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(jwtService, never()).generateToken(any(), any());
    }

    /*----------------------------------------------------------------------------- */
    // Tests for logoutUser and logoutAllSessions

    @Test
    void logoutUser_endsTheSessionOfTheGivenToken() {
        userService.logoutUser(new RefreshTokenRequestDto("refresh"));

        verify(refreshTokenService).endSession("refresh");
    }

    @Test
    void logoutAllSessions_endsEverySessionOfTheUser() {
        userService.logoutAllSessions(userId);

        verify(refreshTokenService).endAllSessions(userId);
    }

    /*----------------------------------------------------------------------------- */
    // Tests for getUserById and getPublicProfileById

    @Test
    void getUserById_withExistingUser_returnsFullProfile() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(buildUser()));

        UserResponseDto response = userService.getUserById(userId);

        assertThat(response.id()).isEqualTo(userId);
        assertThat(response.username()).isEqualTo(USERNAME);
        assertThat(response.email()).isEqualTo(EMAIL);
        assertThat(response.fullName()).isEqualTo(FULLNAME);
    }

    @Test
    void getUserById_withUnknownId_throwsNotFound() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getUserById(userId))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void getPublicProfileById_withExistingUser_returnsPublicData() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(buildUser()));

        PublicUserResponseDto response = userService.getPublicProfileById(userId);

        assertThat(response.username()).isEqualTo(USERNAME);
        assertThat(response.fullName()).isEqualTo(FULLNAME);
    }

    @Test
    void getPublicProfileById_withUnknownId_throwsNotFound() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getPublicProfileById(userId))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    /*----------------------------------------------------------------------------- */
    // Tests for updateUserById

    @Test
    void updateUserById_withAllFields_updatesUser() {
        User user = buildUser();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("newname")).thenReturn(false);
        when(userRepository.save(user)).thenReturn(user);

        UserResponseDto response = userService.updateUserById(userId,
                new UserPatchRequestDto("newname", "New Name", "http://img.png"));

        assertThat(response.username()).isEqualTo("newname");
        assertThat(response.fullName()).isEqualTo("New Name");
        assertThat(user.getImageUrl()).isEqualTo("http://img.png");
        verify(userRepository).save(user);
    }

    @Test
    void updateUserById_withTakenUsername_throwsConflictAndDoesNotSave() {
        User user = buildUser();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.existsByUsername("taken")).thenReturn(true);

        assertThatThrownBy(() -> userService.updateUserById(userId,
                new UserPatchRequestDto("taken", null, null)))
                .isInstanceOf(ConflictException.class);

        assertThat(user.getUsername()).isEqualTo(USERNAME);
        verify(userRepository, never()).save(any());
    }

    @Test
    void updateUserById_withSameUsername_doesNotCheckUniqueness() {
        User user = buildUser();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        userService.updateUserById(userId, new UserPatchRequestDto(USERNAME, "New Name", null));

        verify(userRepository, never()).existsByUsername(any());
        assertThat(user.getFullName()).isEqualTo("New Name");
    }

    @Test
    void updateUserById_withNullFields_keepsExistingValues() {
        User user = buildUser();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        UserResponseDto response = userService.updateUserById(userId,
                new UserPatchRequestDto(null, null, null));

        assertThat(response.username()).isEqualTo(USERNAME);
        assertThat(response.fullName()).isEqualTo(FULLNAME);
    }

    @Test
    void updateUserById_withUnknownId_throwsNotFound() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.updateUserById(userId,
                new UserPatchRequestDto("newname", null, null)))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void updateUserById_onlyImageUrl_leavesOtherFieldsUntouched() {
        User user = buildUser();
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.save(user)).thenReturn(user);

        userService.updateUserById(userId, new UserPatchRequestDto(null, null, "http://img.png"));

        assertThat(user.getImageUrl()).isEqualTo("http://img.png");
        assertThat(user.getUsername()).isEqualTo(USERNAME);
        assertThat(user.getFullName()).isEqualTo(FULLNAME);
        verify(userRepository, never()).existsByUsername(any());
    }

    /*- --------------------------------------------------------------------- */
    // Helpers

    private User buildUser() {
        return User.builder()
                .id(userId)
                .username(USERNAME)
                .email(EMAIL)
                .fullName(FULLNAME)
                .passwordHash(HASH)
                .build();
    }
}