package com.polduu.service;

import java.util.Optional;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
import com.polduu.repository.UserRepository;
import com.polduu.security.JwtService;

import org.springframework.transaction.annotation.Transactional;


@Service 
@Transactional 
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserMapper userMapper;

    // Checked when the email is unknown or has no password, so every failed login costs one
    // password hash comparison and response times don't reveal which emails are registered
    private final String dummyPasswordHash;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService
            , RefreshTokenService refreshTokenService, UserMapper userMapper
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.userMapper = userMapper;
        this.dummyPasswordHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    public AuthResponseDto createUser(UserRegisterRequestDto user) {

        if (userRepository.existsByEmail(user.email())) {
            throw new ConflictException("Email already exists");
        }
        if (userRepository.existsByUsername(user.username())) {
            throw new ConflictException("Username already exists");
        }
        User newUser = userMapper.toEntity(user, passwordEncoder.encode(user.password()), AuthProvider.LOCAL);
        User savedUser = userRepository.save(newUser);
        RefreshTokenService.Session session = refreshTokenService.startSession(savedUser);
        String token = jwtService.generateToken(savedUser.getId(), session.id());

        return toAuthResponseDto(savedUser, token, session.refreshToken());
    }

    public AuthResponseDto googleLogin(GoogleAuthRequestDto googleAuthRequest) {
        throw new UnsupportedOperationException("Google login is not implemented");
    }

    public AuthResponseDto githubLogin(GitHubAuthRequestDto githubAuthRequest) {
        throw new UnsupportedOperationException("GitHub login is not implemented");
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
