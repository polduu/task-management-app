package com.polduu.service;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionOperations;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.GitHubAuthRequestDto;
import com.polduu.dto.auth.GoogleAuthRequestDto;
import com.polduu.dto.auth.RefreshTokenRequestDto;
import com.polduu.dto.auth.UserLoginRequestDto;
import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.dto.user.*;
import com.polduu.exception.ConflictException;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.exception.ResourceNotFoundException;
import com.polduu.mapper.UserMapper;
import com.polduu.model.AuthProvider;
import com.polduu.model.User;
import com.polduu.model.UserIdentity;
import com.polduu.repository.UserIdentityRepository;
import com.polduu.repository.UserRepository;
import com.polduu.security.JwtService;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Service 
@Transactional 
public class UserService {

    private final UserRepository userRepository;
    private final UserIdentityRepository userIdentityRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserMapper userMapper;
    private final GoogleAuthClient googleAuthClient;
    private final GitHubClient gitHubClient;
    private final TransactionOperations transactions;

    // Checked when the email is unknown or has no password, so every failed login costs one
    // password hash comparison and response times don't reveal which emails are registered
    private final String dummyPasswordHash;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
            RefreshTokenService refreshTokenService, UserMapper userMapper,
            GoogleAuthClient googleAuthClient, UserIdentityRepository userIdentityRepository,
            GitHubClient gitHubClient, TransactionOperations transactions) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.userMapper = userMapper;
        this.googleAuthClient = googleAuthClient;
        this.userIdentityRepository = userIdentityRepository;
        this.gitHubClient = gitHubClient;
        this.transactions = transactions;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public AuthResponseDto createUser(UserRegisterRequestDto user) {

        if (userRepository.existsByEmail(user.email())) {
            throw new ConflictException("Email already exists");
        }
        if (userRepository.existsByUsername(user.username())) {
            throw new ConflictException("Username already exists");
        }
        User newUser = userMapper.toEntity(user, passwordEncoder.encode(user.password()));
        User savedUser = userRepository.save(newUser);
        RefreshTokenService.Session session = refreshTokenService.startSession(savedUser);
        String token = jwtService.generateToken(savedUser.getId(), session.id());

        return toAuthResponseDto(savedUser, token, session.refreshToken());
    }

    public AuthResponseDto googleLogin(GoogleAuthRequestDto googleAuthRequest) {
        GoogleIdToken.Payload payload = googleAuthClient.verify(googleAuthRequest.idToken());

        if (payload.getEmail() == null || !Boolean.TRUE.equals(payload.getEmailVerified())) {
            log.warn("Google login rejected: email missing or not verified");
            throw new InvalidCredentialsException();
        }
        String email = payload.getEmail().trim().toLowerCase(Locale.ROOT);

        String name = (String) payload.get("name");
        String providerId = payload.getSubject();

        User user = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
                .map(UserIdentity::getUser)
                .orElseGet(() -> createSocialUser(email, name, AuthProvider.GOOGLE, providerId));

        return startSessionFor(user);
    }

    private String generateUsername(String name) {
        String base = Normalizer.normalize(name == null ? "" : name, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "")               // quita acentos
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "_")          // resto de caracteres a _
                .replaceAll("^_|_$", "");

        if (base.length() < 3) {
            base = "user";
        }
        base = base.substring(0, Math.min(base.length(), 40)); // deja sitio al sufijo

        String candidate = base;
        while (userRepository.existsByUsername(candidate)) {
            candidate = base + "_" + UUID.randomUUID().toString().substring(0, 4);
        }
        return candidate;
        }


    // No transaction while waiting for GitHub, so a slow response doesn't hold a database connection
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public AuthResponseDto githubLogin(GitHubAuthRequestDto request) {
        String accessToken = gitHubClient.exchangeCode(request.code());
        GitHubClient.Profile profile = gitHubClient.fetchProfile(accessToken);

        // The email is only needed to create an account: linked users don't depend on it
        User user = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, profile.id())
                .map(UserIdentity::getUser)
                .orElseGet(() -> {
                    String email = gitHubClient.fetchPrimaryVerifiedEmail(accessToken)
                            .trim().toLowerCase(Locale.ROOT);
                    return transactions.execute(status ->
                            createSocialUser(email, profile.name(), AuthProvider.GITHUB, profile.id()));
                });

        return startSessionFor(user);
    }

    // An existing account with the same email is never taken over: it has to link the provider itself
    private User createSocialUser(String email, String name, AuthProvider provider, String providerId) {
        if (userRepository.existsByEmail(email)) {
            log.warn("{} login rejected: email belongs to an account not linked to it", provider);
            throw new ConflictException("Email already exists");
        }
        User created = new User();
        created.setUsername(generateUsername(name));
        created.setEmail(email);
        String fullName = name == null || name.isBlank() ? "User" : name;
        created.setFullName(fullName.substring(0, Math.min(fullName.length(), 100)));
        User saved = userRepository.save(created);
        userIdentityRepository.save(UserIdentity.of(saved, provider, providerId));
        return saved;
    }

    private AuthResponseDto startSessionFor(User user) {
        RefreshTokenService.Session session = refreshTokenService.startSession(user);
        String token = jwtService.generateToken(user.getId(), session.id());
        return toAuthResponseDto(user, token, session.refreshToken());
    }

    @Transactional(readOnly = true)
    public UserResponseDto getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        return userMapper.toResponse(user);
    }

    public AuthResponseDto logInUser(UserLoginRequestDto request) {
        
        Optional<User> found = userRepository.findByEmail(request.email());
        String storedHash = found.map(User::getPasswordHash).orElse(null);

        // Always run the hash comparison, even when it can't succeed (see dummyPasswordHash)
        boolean passwordMatches = passwordEncoder.matches(request.password(),
                storedHash != null ? storedHash : dummyPasswordHash);
        if (storedHash == null || !passwordMatches) {
            throw new InvalidCredentialsException();
        }

        User user = found.get();
        RefreshTokenService.Session session = refreshTokenService.startSession(user);
        String token = jwtService.generateToken(user.getId(), session.id());

        return toAuthResponseDto(user, token, session.refreshToken());
    }  
    public UserResponseDto updateUserById(UUID id, UserPatchRequestDto request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        if (request.username() != null && !request.username().equals(user.getUsername())) {
            if (userRepository.existsByUsername(request.username())) {
                throw new ConflictException("Username already exists"); 
            }
            user.setUsername(request.username());
        }
        if (request.fullName() != null) {
            user.setFullName(request.fullName());
        }
        if (request.imageUrl() != null) {
            user.setImageUrl(request.imageUrl());
        }

        User updatedUser = userRepository.save(user);

        return userMapper.toResponse(updatedUser);
    }

    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public AuthResponseDto refreshToken(RefreshTokenRequestDto refreshTokenRequest) {

        RefreshTokenService.Rotation rotation = refreshTokenService.rotate(refreshTokenRequest.refreshToken());

        User user = rotation.user();
        String accessToken = jwtService.generateToken(user.getId(), rotation.sessionId());

        return toAuthResponseDto(user, accessToken, rotation.refreshToken());
    }

    private AuthResponseDto toAuthResponseDto(User user, String token, String refreshToken) {
        Long expiresIn = jwtService.getJwtExpirationTime(); // Get expiration time in seconds
        return new AuthResponseDto(
            token,
            refreshToken,
            expiresIn,
            userMapper.toResponse(user)
        );
    }

    public PublicUserResponseDto getPublicProfileById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return new PublicUserResponseDto(
            user.getUsername(),
            user.getFullName(),
            user.getImageUrl()
        );
    }

    public void logoutUser(RefreshTokenRequestDto request) {
        refreshTokenService.endSession(request.refreshToken());
    }

    // Access tokens die with their session: the filter rejects them once it is revoked
    public void logoutAllSessions(UUID userId) {
        refreshTokenService.endAllSessions(userId);
    }
}
