package com.polduu.controller;

import com.polduu.dto.auth.LinkGitHubRequestDto;
import com.polduu.dto.auth.LinkGoogleRequestDto;
import com.polduu.dto.auth.LinkedAccountsResponseDto;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import com.polduu.exception.ReauthenticationRequiredException;
import com.polduu.model.AuthProvider;
import java.util.Locale;
import static org.mockito.Mockito.doThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;
import io.jsonwebtoken.JwtException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;

import com.polduu.dto.auth.AuthResponseDto;
import org.springframework.web.client.RestClientException;
import com.polduu.dto.user.UserResponseDto;
import com.polduu.exception.ConflictException;
import com.polduu.exception.ExternalAccountRejectedException;
import com.polduu.exception.GlobalExceptionHandler;
import com.polduu.exception.InvalidCredentialsException;
import com.polduu.exception.InvalidRefreshTokenException;
import com.polduu.security.JwtService;
import com.polduu.security.SecurityConfig;
import com.polduu.service.RefreshTokenService;
import com.polduu.service.AccountLinkingService;
import com.polduu.service.UserService;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class AuthControllerTest {

        @Autowired MockMvc mockMvc;

        @MockitoBean UserService userService;
        @MockitoBean AccountLinkingService accountLinkingService;
        @MockitoBean JwtService jwtService; // lo necesita JwtAuthenticationFilter
        @MockitoBean RefreshTokenService refreshTokenService; // idem

        private static final String EMAIL = "pol@test.com";
        private static final String USERNAME = "pol";
        private static final String FULLNAME = "Pol";
        private static final String REFRESH_TOKEN = "refresh";
        private static final String ACCESS_TOKEN = "access";

        // Login Tests

        @Test
        void login_withValidCredentials_returns200() throws Exception {
                var response = new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null));
                when(userService.logInUser(any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"email":"pol@test.com","password":"secret123"}
                        """))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken").value("access"))
                        .andExpect(jsonPath("$.refreshToken").value("refresh"));
        }

        @Test
        void login_withInvalidCredentials_returns401() throws Exception {
                when(userService.logInUser(any()))
                        .thenThrow(new InvalidCredentialsException());

                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"email":"pol@test.com","password":"wrong"}
                        """))
                        .andExpect(status().isUnauthorized())
                        .andExpect(jsonPath("$.message").value("Invalid credentials"));
        }

        @Test
        void login_withInvalidBody_returns400WithFieldErrors() throws Exception {
                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors").exists());
        }

        @Test
        void login_withExpiredBearerToken_stillWorks() throws Exception {
                when(jwtService.parseAccessToken(any())).thenThrow(new JwtException("expired"));
                when(userService.logInUser(any())).thenReturn(new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null)));

        mockMvc.perform(post("/api/auth/login")
                .header("Authorization", "Bearer expired.token")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"pol@test.com","password":"secret123"}
                        """))
                .andExpect(status().isOk());
        }

        @Test
        void login_withMalformedJson_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.message").value("Malformed request body"));
        }

        @Test
        void login_withWrongContentType_returns415() throws Exception {
                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("hello"))
                        .andExpect(status().isUnsupportedMediaType());
        }

        /*------------------------------------------------------------------------------------------------*/

        // Register Tests
        @Test
        void register_withValidBody_returns201() throws Exception {
                var response = new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L, 
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null));
                when(userService.createUser(any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"username":"pol","email":"pol@test.com","password":"secret123", "fullName":"Pol"}
                        """))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.accessToken").value("access"))
                        .andExpect(jsonPath("$.refreshToken").value("refresh"));
        }

        @Test
        void register_withInvalidBody_returns400WithFieldErrors() throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").exists());
        }

        @Test 
        void register_withExistingEmail_returns409() throws Exception {
                when(userService.createUser(any()))
                        .thenThrow(new ConflictException("Email already exists"));

                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"username":"pol","email":"pol@test.com","password":"secret123", "fullName":"Pol"}
                        """))
                        .andExpect(status().isConflict())
                        .andExpect(jsonPath("$.message").value("Email already exists"));
        }

        @Test
        void register_withInvalidEmail_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"pol","email":"not-an-email","password":"secret123","fullName":"Pol"}
                                """))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.email").exists());
        }

        @Test
        void register_withShortPassword_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"pol","email":"pol@test.com","password":"123","fullName":"Pol"}
                                """))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.password").exists());
        }

        @ParameterizedTest
        @ValueSource(strings = {"ab", "a b", "pol!", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
        void register_withInvalidUsername_returns400(String username) throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody(username, "pol@test.com", "secret123", "Pol")))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.username").exists());

                verify(userService, never()).createUser(any());
        }

        @Test
        void register_withTooLongFullName_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody("pol", "pol@test.com", "secret123", "a".repeat(101))))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.fullName").exists());
        }

        // BCrypt only uses the first 72 bytes; "ñ" takes 2 bytes in UTF-8
        @Test
        void register_withPasswordOf72Bytes_returns201() throws Exception {
                when(userService.createUser(any())).thenReturn(new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null)));

                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody("pol", "pol@test.com", "ñ".repeat(36), "Pol")))
                        .andExpect(status().isCreated());
        }

        @Test
        void register_withPasswordOver72Bytes_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody("pol", "pol@test.com", "ñ".repeat(37), "Pol")))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.password").value("Password is too long"));

                verify(userService, never()).createUser(any());
        }

        @Test
        void register_normalizesEmailToLowercase() throws Exception {
                when(userService.createUser(any())).thenReturn(new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null)));

                mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerBody("pol", " Pol@Test.COM ", "secret123", "Pol")))
                        .andExpect(status().isCreated());

                verify(userService).createUser(argThat(request -> request.email().equals("pol@test.com")));
        }

        @Test
        void login_normalizesEmailToLowercase() throws Exception {
                when(userService.logInUser(any())).thenReturn(new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null)));

                mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"email":" Pol@Test.COM ","password":"secret123"}
                        """))
                        .andExpect(status().isOk());

                verify(userService).logInUser(argThat(request -> request.email().equals("pol@test.com")));
        }

        private static String registerBody(String username, String email, String password, String fullName) {
                return """
                        {"username":"%s","email":"%s","password":"%s","fullName":"%s"}
                        """.formatted(username, email, password, fullName);
        }

        /*------------------------------------------------------------------------------------------------*/

        // Refresh Token Tests

        @Test 
        void refreshToken_withValidBody_returns200() throws Exception {
                var response = new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L, 
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null));
                when(userService.refreshToken(any())).thenReturn(response);

                mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"refreshToken":"refresh"}
                        """))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken").value("access"))
                        .andExpect(jsonPath("$.refreshToken").value("refresh"));
        }

        @Test 
        void refreshToken_withInvalidBody_returns400WithFieldErrors() throws Exception {
                mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors").exists());
        }

        @Test
        void refreshToken_withInvalidToken_returns401() throws Exception {
                when(userService.refreshToken(any()))
                        .thenThrow(new InvalidRefreshTokenException("Invalid refresh token"));

                mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"refreshToken":"invalid"}
                        """))
                        .andExpect(status().isUnauthorized())
                        .andExpect(jsonPath("$.message").value("Invalid refresh token"));
        }

        /*------------------------------------------------------------------------------------------------*/

        // Logout Tests

        @Test 
        void logoutUser_withValidBody_returns204() throws Exception {
                mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"refreshToken":"refresh"}
                        """))
                        .andExpect(status().isNoContent());
                
                verify(userService).logoutUser(any());
        }

        @Test 
        void logoutUser_withInvalidBody_returns400WithFieldErrors() throws Exception {
                mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors").exists());
        }

        /*------------------------------------------------------------------------------------------------*/

        // Logout-all Tests

        @Test
        void logoutAllSessions_withToken_endsEverySessionOfThatUser() throws Exception {
                UUID userId = UUID.randomUUID();

                mockMvc.perform(post("/api/auth/logout-all")
                        .with(authentication(new UsernamePasswordAuthenticationToken(userId, null, List.of()))))
                        .andExpect(status().isNoContent());

                verify(userService).logoutAllSessions(userId);
        }

        @Test
        void logoutAllSessions_withoutToken_returns401() throws Exception {
                mockMvc.perform(post("/api/auth/logout-all"))
                        .andExpect(status().isUnauthorized());

                verify(userService, never()).logoutAllSessions(any());
        }

        // Google Tests

        @Test
        void googleLogin_withoutAccessToken_returns200() throws Exception {
                when(userService.googleLogin(any())).thenReturn(new AuthResponseDto(ACCESS_TOKEN, REFRESH_TOKEN, 900L,
                        new UserResponseDto(UUID.randomUUID(), USERNAME, EMAIL, FULLNAME, null)));

                mockMvc.perform(post("/api/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"idToken":"id-token"}
                        """))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken").value(ACCESS_TOKEN));
        }

        @Test
        void googleLogin_withBlankIdToken_returns400() throws Exception {
                mockMvc.perform(post("/api/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"idToken":" "}
                        """))
                        .andExpect(status().isBadRequest())
                        .andExpect(jsonPath("$.fieldErrors.idToken").exists());

                verify(userService, never()).googleLogin(any());
        }

        @Test
        void linkGoogle_withToken_linksThatUser() throws Exception {
                UUID userId = UUID.randomUUID();
                UUID sessionId = UUID.randomUUID();

                mockMvc.perform(post("/api/auth/google/link")
                        .with(authentication(session(userId, sessionId)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"idToken":"id-token"}
                        """))
                        .andExpect(status().isNoContent());

                verify(accountLinkingService).linkGoogleAccount(userId, sessionId, new LinkGoogleRequestDto("id-token", null));
        }

        @Test
        void linkGoogle_withoutToken_returns401() throws Exception {
                mockMvc.perform(post("/api/auth/google/link")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"idToken":"id-token"}
                        """))
                        .andExpect(status().isUnauthorized());

                verify(accountLinkingService, never()).linkGoogleAccount(any(), any(), any());
        }

        @Test
        void linkGitHub_withAuthenticatedUser_returns204() throws Exception {
                UUID userId = UUID.randomUUID();
                UUID sessionId = UUID.randomUUID();

                mockMvc.perform(post("/api/auth/github/link")
                        .with(authentication(session(userId, sessionId)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"code":"gh-code"}
                        """))
                        .andExpect(status().isNoContent());

                verify(accountLinkingService).linkGitHubAccount(userId, sessionId, new LinkGitHubRequestDto("gh-code", null));
        }

        @Test
        void linkGitHub_withoutToken_returns401() throws Exception {
                mockMvc.perform(post("/api/auth/github/link")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"code":"gh-code"}
                        """))
                        .andExpect(status().isUnauthorized());

                verify(accountLinkingService, never()).linkGitHubAccount(any(), any(), any());
        }

        @Test
        void githubLogin_whenGitHubIsUnavailable_returns502() throws Exception {
                when(userService.githubLogin(any())).thenThrow(new RestClientException("boom"));

                mockMvc.perform(post("/api/auth/github")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"code":"gh-code"}
                        """))
                        .andExpect(status().isBadGateway())
                        .andExpect(jsonPath("$.message").value("External service unavailable"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"google", "github"})
        void unlink_withAuthenticatedUser_returns204(String provider) throws Exception {
                UUID userId = UUID.randomUUID();
                UUID sessionId = UUID.randomUUID();

                mockMvc.perform(post("/api/auth/" + provider + "/unlink")
                        .with(authentication(session(userId, sessionId)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"password":"secret"}
                        """))
                        .andExpect(status().isNoContent());

                verify(accountLinkingService).unlinkAccount(userId, sessionId,
                        AuthProvider.valueOf(provider.toUpperCase(Locale.ROOT)), "secret");
        }

        @ParameterizedTest
        @ValueSource(strings = {"google", "github"})
        void unlink_withoutToken_returns401(String provider) throws Exception {
                mockMvc.perform(post("/api/auth/" + provider + "/unlink")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                        .andExpect(status().isUnauthorized());

                verify(accountLinkingService, never()).unlinkAccount(any(), any(), any(), any());
        }

        @Test
        void unlink_withoutReauthentication_returns403() throws Exception {
                doThrow(new ReauthenticationRequiredException("Password confirmation required"))
                        .when(accountLinkingService).unlinkAccount(any(), any(), any(), any());

                mockMvc.perform(post("/api/auth/github/unlink")
                        .with(authentication(session(UUID.randomUUID(), UUID.randomUUID())))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                        .andExpect(status().isForbidden())
                        .andExpect(jsonPath("$.message").value("Password confirmation required"));
        }

        @Test
        void identities_withAuthenticatedUser_returnsTheirLinkedAccounts() throws Exception {
                UUID userId = UUID.randomUUID();
                when(accountLinkingService.getLinkedAccounts(userId))
                        .thenReturn(new LinkedAccountsResponseDto(List.of(AuthProvider.GITHUB), true));

                mockMvc.perform(get("/api/auth/identities")
                        .with(authentication(session(userId, UUID.randomUUID()))))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.providers[0]").value("GITHUB"))
                        .andExpect(jsonPath("$.hasPassword").value(true));
        }

        @Test
        void identities_withoutToken_returns401() throws Exception {
                mockMvc.perform(get("/api/auth/identities"))
                        .andExpect(status().isUnauthorized());

                verify(accountLinkingService, never()).getLinkedAccounts(any());
        }

        @Test
        void linkGitHub_withRejectedCode_returns400() throws Exception {
                doThrow(new ExternalAccountRejectedException())
                        .when(accountLinkingService).linkGitHubAccount(any(), any(), any());

                mockMvc.perform(post("/api/auth/github/link")
                        .with(authentication(session(UUID.randomUUID(), UUID.randomUUID())))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {"code":"gh-code"}
                        """))
                        .andExpect(status().isBadRequest());
        }

        private static UsernamePasswordAuthenticationToken session(UUID userId, UUID sessionId) {
                UsernamePasswordAuthenticationToken token =
                        new UsernamePasswordAuthenticationToken(userId, null, List.of());
                token.setDetails(sessionId);
                return token;
        }
}
