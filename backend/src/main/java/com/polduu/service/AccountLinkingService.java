package com.polduu.service;

import java.time.Duration;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.polduu.dto.auth.LinkGitHubRequestDto;
import com.polduu.dto.auth.LinkGoogleRequestDto;
import com.polduu.dto.auth.LinkedAccountsResponseDto;
import com.polduu.exception.ConflictException;
import com.polduu.exception.ExternalAccountRejectedException;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.exception.ReauthenticationRequiredException;
import com.polduu.exception.ResourceNotFoundException;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;

import lombok.extern.slf4j.Slf4j;

/** Sign-in methods of an existing account: listing, linking and unlinking external providers. */
@Slf4j
@Service
@Transactional
public class AccountLinkingService {

    // How fresh a login must be to change sign-in methods on an account without a password
    static final Duration RECENT_LOGIN_WINDOW = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final UserIdentityRepository userIdentityRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final GoogleAuthClient googleAuthClient;
    private final GitHubClient gitHubClient;
    private final TransactionOperations transactions;

    public AccountLinkingService(UserRepository userRepository, UserIdentityRepository userIdentityRepository,
            PasswordEncoder passwordEncoder, RefreshTokenService refreshTokenService,
            GoogleAuthClient googleAuthClient, GitHubClient gitHubClient, TransactionOperations transactions) {
        this.userRepository = userRepository;
        this.userIdentityRepository = userIdentityRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.googleAuthClient = googleAuthClient;
        this.gitHubClient = gitHubClient;
        this.transactions = transactions;
    }

    @Transactional(readOnly = true)
    public LinkedAccountsResponseDto getLinkedAccounts(UUID userId) {
        boolean hasPassword = findUser(userId).getPasswordHash() != null;
        return new LinkedAccountsResponseDto(
                userIdentityRepository.findByUserId(userId).stream()
                        .map(UserIdentity::getProvider)
                        .sorted()
                        .toList(),
                hasPassword);
    }

    public void linkGoogleAccount(UUID userId, UUID sessionId, LinkGoogleRequestDto request) {
        requireReauthentication(findUser(userId), request.password(), sessionId);

        GoogleIdToken.Payload payload = verifyExternalAccount(() -> googleAuthClient.verify(request.idToken()));
        if (!Boolean.TRUE.equals(payload.getEmailVerified())) {
            log.warn("Google link rejected for user {}: email not verified", userId);
            throw new ExternalAccountRejectedException();
        }
        addIdentity(userId, AuthProvider.GOOGLE, payload.getSubject());
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void linkGitHubAccount(UUID userId, UUID sessionId, LinkGitHubRequestDto request) {
        requireReauthentication(findUser(userId), request.password(), sessionId);

        String providerId = verifyExternalAccount(
                () -> gitHubClient.fetchProfile(gitHubClient.exchangeCode(request.code())).id());
        transactions.executeWithoutResult(status -> addIdentity(userId, AuthProvider.GITHUB, providerId));
    }

    // The clients report a rejected token as invalid credentials, which would read as an expired session here
    private static <T> T verifyExternalAccount(Supplier<T> verification) {
        try {
            return verification.get();
        } catch (InvalidCredentialsException e) {
            throw new ExternalAccountRejectedException();
        }
    }

    // Never leaves the account without a way to sign in
    public void unlinkAccount(UUID userId, UUID sessionId, AuthProvider provider, String password) {
        User user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        requireReauthentication(user, password, sessionId);

        UserIdentity identity = userIdentityRepository.findByUserIdAndProvider(userId, provider)
                .orElseThrow(() -> new ResourceNotFoundException("Account not linked"));
        if (user.getPasswordHash() == null && userIdentityRepository.countByUserId(userId) <= 1) {
            throw new ConflictException("Cannot unlink the only sign-in method");
        }
        userIdentityRepository.delete(identity);
        log.info("{} account unlinked from user {}", provider, userId);
    }

    // A stolen access token alone must not be enough to change how the account is accessed
    private void requireReauthentication(User user, String password, UUID sessionId) {
        if (user.getPasswordHash() != null) {
            if (password == null || !passwordEncoder.matches(password, user.getPasswordHash())) {
                throw new ReauthenticationRequiredException("Password confirmation required");
            }
        } else if (!refreshTokenService.startedWithin(sessionId, RECENT_LOGIN_WINDOW)) {
            throw new ReauthenticationRequiredException("Recent login required");
        }
    }

    private void addIdentity(UUID userId, AuthProvider provider, String providerId) {
        User user = findUser(userId);
        boolean linkedElsewhere = userIdentityRepository.findByProviderAndProviderId(provider, providerId)
                .filter(other -> !other.getUser().getId().equals(userId))
                .isPresent();
        if (linkedElsewhere) {
            log.warn("{} link rejected for user {}: account linked to another user", provider, userId);
            throw new ConflictException("External account already linked");
        }
        if (userIdentityRepository.existsByUserIdAndProvider(userId, provider)) {
            log.warn("{} link rejected for user {}: already linked", provider, userId);
            throw new ConflictException("External account already linked");
        }
        userIdentityRepository.save(UserIdentity.of(user, provider, providerId));
        log.info("{} account linked to user {}", provider, userId);
    }

    private User findUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }
}
