package com.polduu.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.polduu.exception.ConflictException;
import com.polduu.exception.ReauthenticationRequiredException;
import com.polduu.exception.ResourceNotFoundException;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class AccountUnlinkServiceTest {

    @Mock UserRepository userRepository;
    @Mock UserIdentityRepository userIdentityRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock RefreshTokenService refreshTokenService;

    @InjectMocks AccountLinkingService accountLinkingService;

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();
    private final UserIdentity identity = new UserIdentity();

    @Test
    void unlink_withCorrectPassword_deletesTheIdentity() {
        givenUser("hash");
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        givenLinkedIdentity();

        accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, "secret");

        verify(userIdentityRepository).delete(identity);
    }

    @Test
    void unlink_withWrongPassword_isRejectedEvenAfterARecentLogin() {
        givenUser("hash");

        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, "wrong"))
                .isInstanceOf(ReauthenticationRequiredException.class);

        verify(refreshTokenService, never()).startedWithin(any(), any());
        verify(userIdentityRepository, never()).delete(any());
    }

    @Test
    void unlink_withoutPasswordOnTheAccountAndAnOldLogin_isRejected() {
        givenUser(null);

        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, null))
                .isInstanceOf(ReauthenticationRequiredException.class);

        verify(userIdentityRepository, never()).delete(any());
    }

    @Test
    void unlink_ofTheOnlySignInMethod_throwsConflict() {
        givenUser(null);
        givenRecentLogin();
        givenLinkedIdentity();
        when(userIdentityRepository.countByUserId(userId)).thenReturn(1L);

        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, null))
                .isInstanceOf(ConflictException.class);

        verify(userIdentityRepository, never()).delete(any());
    }

    @Test
    void unlink_withAnotherProviderLeft_deletesTheIdentity() {
        givenUser(null);
        givenRecentLogin();
        givenLinkedIdentity();
        when(userIdentityRepository.countByUserId(userId)).thenReturn(2L);

        accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, null);

        verify(userIdentityRepository).delete(identity);
    }

    @Test
    void unlink_ofAProviderThatIsNotLinked_throwsNotFound() {
        givenUser(null);
        givenRecentLogin();

        assertThatThrownBy(() -> accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, null))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    private void givenUser(String passwordHash) {
        User user = User.builder().id(userId).passwordHash(passwordHash).build();
        when(userRepository.findByIdForUpdate(userId)).thenReturn(Optional.of(user));
    }

    private void givenRecentLogin() {
        when(refreshTokenService.startedWithin(sessionId, AccountLinkingService.RECENT_LOGIN_WINDOW)).thenReturn(true);
    }

    private void givenLinkedIdentity() {
        when(userIdentityRepository.findByUserIdAndProvider(userId, AuthProvider.GITHUB))
                .thenReturn(Optional.of(identity));
    }
}
