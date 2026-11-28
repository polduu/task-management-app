package com.polduu.controller;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.polduu.dto.auth.AuthResponseDto;
import com.polduu.dto.auth.GitHubAuthRequestDto;
import com.polduu.dto.auth.GoogleAuthRequestDto;
import com.polduu.dto.auth.LinkGitHubRequestDto;
import com.polduu.dto.auth.LinkGoogleRequestDto;
import com.polduu.dto.auth.LinkedAccountsResponseDto;
import com.polduu.dto.auth.RefreshTokenRequestDto;
import com.polduu.dto.auth.UnlinkAccountRequestDto;
import com.polduu.dto.auth.UserLoginRequestDto;
import com.polduu.dto.auth.UserRegisterRequestDto;
import com.polduu.model.AuthProvider;
import com.polduu.service.AccountLinkingService;
import com.polduu.service.UserService;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;


@RestController
@Slf4j 
@Tag (name = "Auth Controller", description = "Controller for user authentication operations")
@RequestMapping ("/api/auth")
public class AuthController {

    private final UserService userService;
    private final AccountLinkingService accountLinkingService;

    public AuthController(UserService userService, AccountLinkingService accountLinkingService) {
        this.userService = userService;
        this.accountLinkingService = accountLinkingService;
    }

    @PostMapping ("/register")
    @ResponseStatus (code = HttpStatus.CREATED)
    public AuthResponseDto createUser(@Valid @RequestBody UserRegisterRequestDto user) {
        log.info("Register endpoint hit");
        return userService.createUser(user);
    }

    @PostMapping ("/google")
    public AuthResponseDto googleLogin(@Valid @RequestBody GoogleAuthRequestDto googleAuthRequest) {
        log.info("Google login endpoint hit");
        return userService.googleLogin(googleAuthRequest);
    }

    @GetMapping ("/identities")
    public LinkedAccountsResponseDto getLinkedAccounts(@AuthenticationPrincipal UUID userId) {
        return accountLinkingService.getLinkedAccounts(userId);
    }

    @PostMapping ("/google/link")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void linkGoogle(@AuthenticationPrincipal UUID userId,
            @CurrentSecurityContext(expression = "authentication.details") UUID sessionId,
            @Valid @RequestBody LinkGoogleRequestDto request) {
        log.info("Google link endpoint hit");
        accountLinkingService.linkGoogleAccount(userId, sessionId, request);
    }

    @PostMapping ("/google/unlink")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void unlinkGoogle(@AuthenticationPrincipal UUID userId,
            @CurrentSecurityContext(expression = "authentication.details") UUID sessionId,
            @Valid @RequestBody UnlinkAccountRequestDto request) {
        log.info("Google unlink endpoint hit");
        accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GOOGLE, request.password());
    }

    @PostMapping ("/github")
    public AuthResponseDto githubLogin(@Valid @RequestBody GitHubAuthRequestDto githubAuthRequest) {
        log.info("GitHub login endpoint hit");
        return userService.githubLogin(githubAuthRequest);
    }

    @PostMapping ("/github/link")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void linkGitHub(@AuthenticationPrincipal UUID userId,
            @CurrentSecurityContext(expression = "authentication.details") UUID sessionId,
            @Valid @RequestBody LinkGitHubRequestDto request) {
        log.info("GitHub link endpoint hit");
        accountLinkingService.linkGitHubAccount(userId, sessionId, request);
    }

    @PostMapping ("/github/unlink")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void unlinkGitHub(@AuthenticationPrincipal UUID userId,
            @CurrentSecurityContext(expression = "authentication.details") UUID sessionId,
            @Valid @RequestBody UnlinkAccountRequestDto request) {
        log.info("GitHub unlink endpoint hit");
        accountLinkingService.unlinkAccount(userId, sessionId, AuthProvider.GITHUB, request.password());
    }

    @PostMapping ("/login")
    public AuthResponseDto loginUser(@Valid @RequestBody UserLoginRequestDto userLoginRequestDto) {
        log.info("Login endpoint hit");
        return userService.logInUser(userLoginRequestDto);
    }

    @PostMapping ("/refresh")
    public AuthResponseDto refreshToken(@Valid @RequestBody RefreshTokenRequestDto refreshTokenRequest) {
        log.info("Refreshing token");
        return userService.refreshToken(refreshTokenRequest);
    }

    @PostMapping ("/logout")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void logoutUser(@Valid @RequestBody RefreshTokenRequestDto refreshTokenRequest) {
        log.info("Logout endpoint hit");
        userService.logoutUser(refreshTokenRequest);
    }

    // Requires an access token: it is not in the public routes of SecurityConfig
    @PostMapping ("/logout-all")
    @ResponseStatus (code = HttpStatus.NO_CONTENT)
    public void logoutAllSessions(@AuthenticationPrincipal UUID userId) {
        log.info("Logout-all endpoint hit");
        userService.logoutAllSessions(userId);
    }

}
