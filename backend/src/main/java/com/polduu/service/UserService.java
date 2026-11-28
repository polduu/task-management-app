package com.polduu.service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
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


import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;

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

    private final GoogleIdTokenVerifier googleIdTokenVerifier;

    @Value("${github.client-id}")
    private String githubClientId;
    @Value("${github.client-secret}")
    private String githubClientSecret;

    private final RestClient restClient = RestClient.create();

    // Checked when the email is unknown or has no password, so every failed login costs one
    // password hash comparison and response times don't reveal which emails are registered
    private final String dummyPasswordHash;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService
            , RefreshTokenService refreshTokenService, UserMapper userMapper
            , GoogleIdTokenVerifier googleIdTokenVerifier
            , UserIdentityRepository userIdentityRepository
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.userMapper = userMapper;
        this.googleIdTokenVerifier = googleIdTokenVerifier;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
        this.userIdentityRepository = userIdentityRepository;
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
        GoogleIdToken.Payload payload = verifyGoogleToken(googleAuthRequest.idToken());

        if (payload.getEmail() == null || !Boolean.TRUE.equals(payload.getEmailVerified())) {
            log.warn("Google login rejected: email missing or not verified");
            throw new InvalidCredentialsException();
        }
        String email = payload.getEmail().trim().toLowerCase(Locale.ROOT);

        String name = (String) payload.get("name");
        String providerId = payload.getSubject();




        User user = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, providerId)
            .map(UserIdentity::getUser)
            .orElseGet(() -> {
                if (userRepository.existsByEmail(email)) {
                    log.warn("Google login rejected: email belongs to an account not linked to Google");
                    throw new ConflictException("Email already exists");
                }
                User created = new User();
                created.setUsername(generateUsername(name));
                created.setEmail(email);
                String fullName = name == null || name.isBlank() ? "User" : name;
                created.setFullName(fullName.substring(0, Math.min(fullName.length(), 100)));
                UserIdentity userIdentity = new UserIdentity();
                User saved = userRepository.save(created);
                userIdentity.setUser(created);
                userIdentity.setProvider(AuthProvider.GOOGLE);
                userIdentity.setProviderId(providerId);
                userIdentityRepository.save(userIdentity);
                return saved;
            });

        RefreshTokenService.Session session = refreshTokenService.startSession(user);
        String token = jwtService.generateToken(user.getId(), session.id());

        return toAuthResponseDto(user, token, session.refreshToken());
    }

    // The token is never logged: it is a credential and carries personal data
    private GoogleIdToken.Payload verifyGoogleToken(String idTokenString) {
        GoogleIdToken idToken;
        try {
            idToken = googleIdTokenVerifier.verify(idTokenString);
        } catch (IOException | GeneralSecurityException e) {
            log.error("Could not verify Google ID token", e);
            throw new InvalidCredentialsException();
        } catch (RuntimeException e) {
            log.warn("Malformed Google ID token: {}", e.getClass().getSimpleName());
            throw new InvalidCredentialsException();
        }
        if (idToken == null) {
            log.warn("Google ID token rejected by the verifier");
            throw new InvalidCredentialsException();
        }
        return idToken.getPayload();
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


    public AuthResponseDto githubLogin(GitHubAuthRequestDto request) {
        String accessToken = exchangeCodeForAccessToken(request.code());
        Map<String, Object> githubUser = fetchGithubUser(accessToken);

        String providerId = String.valueOf(githubUser.get("id"));
        String name = githubUser.get("name") != null 
                ? (String) githubUser.get("name") 
                : (String) githubUser.get("login");

        String email = fetchPrimaryVerifiedEmail(accessToken);

        final String finalEmail = email.trim().toLowerCase(Locale.ROOT);
        User user = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, providerId)
            .map(UserIdentity::getUser)
            .orElseGet(() -> {
                if (userRepository.existsByEmail(finalEmail)) {
                    log.warn("GitHub login rejected: email belongs to an account not linked to GitHub");
                    throw new ConflictException("Email already exists");
                }
                User created = new User();
                created.setUsername(generateUsername(name));
                created.setEmail(finalEmail);
                String fullName = name == null || name.isBlank() ? "User" : name;
                created.setFullName(fullName.substring(0, Math.min(fullName.length(), 100)));
                User saved = userRepository.save(created);
                UserIdentity userIdentity = new UserIdentity();
                userIdentity.setUser(created);
                userIdentity.setProvider(AuthProvider.GITHUB);
                userIdentity.setProviderId(providerId);
                userIdentityRepository.save(userIdentity);
                return saved;
            });

        RefreshTokenService.Session session = refreshTokenService.startSession(user);
        String jwt = jwtService.generateToken(user.getId(), session.id()); 
        return toAuthResponseDto(user, jwt, session.refreshToken());
    }

    private String exchangeCodeForAccessToken(String code) {
        Map<String, String> body = Map.of(
                "client_id", githubClientId,
                "client_secret", githubClientSecret,
                "code", code
        );

        Map<String, Object> response = restClient.post()
                .uri("https://github.com/login/oauth/access_token")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        if (response == null || !response.containsKey("access_token")) {
            log.warn("GitHub login rejected: could not exchange code for access token");
            throw new InvalidCredentialsException();
        }
        return (String) response.get("access_token");
    }

    private Map<String, Object> fetchGithubUser(String accessToken) {
        Map<String, Object> githubUser = restClient.get()
                .uri("https://api.github.com/user")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        if (githubUser == null || githubUser.get("id") == null) {
            log.warn("GitHub request rejected: could not fetch user profile");
            throw new InvalidCredentialsException();
        }
        return githubUser;
    }

    private String fetchPrimaryVerifiedEmail(String accessToken) {
        List<Map<String, Object>> emails = restClient.get()
                .uri("https://api.github.com/user/emails")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        if (emails == null || emails.isEmpty()) {
            log.warn("GitHub login rejected: could not fetch user emails");
            throw new InvalidCredentialsException();
        }

        return emails.stream()
                .filter(e -> Boolean.TRUE.equals(e.get("primary")) 
                        && Boolean.TRUE.equals(e.get("verified")) 
                        && e.get("email") != null)
                .map(e -> e.get("email").toString())
                .findFirst()
                .orElseThrow(() -> {
                    log.warn("GitHub login rejected: no primary verified email found");
                    return new InvalidCredentialsException();
                });
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

    public void linkGoogleAccount(UUID userId, GoogleAuthRequestDto request) {

        GoogleIdToken.Payload payload = verifyGoogleToken(request.idToken());

        if (!Boolean.TRUE.equals(payload.getEmailVerified())) {
            log.warn("Google link rejected for user {}: email not verified", userId);
            throw new InvalidCredentialsException();
        }
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        boolean linkedElsewhere = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, payload.getSubject())
                .filter(other -> !other.getUser().getId().equals(userId))
                .isPresent();
        if (linkedElsewhere) {
            log.warn("Google link rejected for user {}: Google account linked to another user", userId);
            throw new ConflictException("Google account already linked");
        }
        if (userIdentityRepository.existsByUserIdAndProvider(userId, AuthProvider.GOOGLE)) {
            log.warn("Google link rejected for user {}: already linked", userId);
            throw new ConflictException("Google account already linked");
        }
        UserIdentity userIdentity = new UserIdentity();
        userIdentity.setUser(user);
        userIdentity.setProvider(AuthProvider.GOOGLE);
        userIdentity.setProviderId(payload.getSubject());
        userIdentityRepository.save(userIdentity);
        log.info("Google account linked to user {}", userId);
    }

    public void linkGitHubAccount(UUID userId, GitHubAuthRequestDto request) {
        String accessToken = exchangeCodeForAccessToken(request.code());
        Map<String, Object> githubUser = fetchGithubUser(accessToken);
        String providerId = String.valueOf(githubUser.get("id"));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        boolean linkedElsewhere = userIdentityRepository.findByProviderAndProviderId(AuthProvider.GITHUB, providerId)
                .filter(other -> !other.getUser().getId().equals(userId))
                .isPresent();
        if (linkedElsewhere) {
            log.warn("GitHub link rejected for user {}: GitHub account linked to another user", userId);
            throw new ConflictException("GitHub account already linked");
        }
        if (userIdentityRepository.existsByUserIdAndProvider(userId, AuthProvider.GITHUB)) {
            log.warn("GitHub link rejected for user {}: already linked", userId);
            throw new ConflictException("GitHub account already linked");
        }
        UserIdentity userIdentity = new UserIdentity();
        userIdentity.setUser(user);
        userIdentity.setProvider(AuthProvider.GITHUB);
        userIdentity.setProviderId(providerId);
        userIdentityRepository.save(userIdentity);
        log.info("GitHub account linked to user {}", userId);
    }


    



}
