package com.polduu.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.polduu.config.AppConfig;
import com.polduu.exception.GlobalExceptionHandler;
import com.polduu.security.JwtService;
import com.polduu.security.RateLimiter;
import com.polduu.security.SecurityConfig;
import com.polduu.service.RefreshTokenService;
import com.polduu.service.AccountLinkingService;
import com.polduu.service.UserService;

// Each test uses its own IP or user, so counters don't leak between them
@WebMvcTest(value = AuthController.class, properties = {
        "rate-limit.login-per-email=2",
        "rate-limit.login-per-ip=3",
        "rate-limit.public-per-ip=1",
        "rate-limit.account-per-user=2"
})
@Import({SecurityConfig.class, GlobalExceptionHandler.class, AppConfig.class, RateLimiter.class})
class RateLimitTest {

    @Autowired MockMvc mockMvc;

    @MockitoBean UserService userService;
    @MockitoBean AccountLinkingService accountLinkingService;
    @MockitoBean JwtService jwtService;
    @MockitoBean RefreshTokenService refreshTokenService;

    @Test
    void login_isLimitedPerEmail_soColleaguesOnTheSameIpKeepTheirOwnAttempts() throws Exception {
        for (int i = 0; i < 2; i++) {
            mockMvc.perform(login("10.0.0.1", "ana@test.com")).andExpect(status().isOk());
        }

        mockMvc.perform(login("10.0.0.1", "ANA@test.com"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
        mockMvc.perform(login("10.0.0.2", "ana@test.com")).andExpect(status().isOk());

        verify(userService, times(3)).logInUser(any());
    }

    @Test
    void login_isAlsoLimitedPerIp_acrossEmails() throws Exception {
        for (String email : List.of("a@test.com", "b@test.com", "c@test.com")) {
            mockMvc.perform(login("10.0.0.3", email)).andExpect(status().isOk());
        }

        mockMvc.perform(login("10.0.0.3", "d@test.com")).andExpect(status().isTooManyRequests());
    }

    @Test
    void otherPublicEndpoints_useTheirOwnPerIpLimit() throws Exception {
        mockMvc.perform(google()).andExpect(status().isOk());

        mockMvc.perform(google()).andExpect(status().isTooManyRequests());
    }

    @Test
    void publicRoutes_areLimitedPerIpEvenWithAToken() throws Exception {
        for (int i = 0; i < 2; i++) {
            UsernamePasswordAuthenticationToken freshUser =
                    new UsernamePasswordAuthenticationToken(UUID.randomUUID(), null, List.of());
            var result = mockMvc.perform(google().with(from("10.0.0.4")).with(authentication(freshUser)));
            result.andExpect(i == 0 ? status().isOk() : status().isTooManyRequests());
        }
    }

    @Test
    void encodedPath_sharesTheLimitOfTheRoute() throws Exception {
        mockMvc.perform(google().with(from("10.0.0.5"))).andExpect(status().isOk());

        mockMvc.perform(post(URI.create("/api/auth/googl%65"))
                        .with(from("10.0.0.5"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"idToken\":\"id-token\"}"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void accountChanges_shareOneLimitPerUser() throws Exception {
        UsernamePasswordAuthenticationToken user =
                new UsernamePasswordAuthenticationToken(UUID.randomUUID(), null, List.of());

        for (String provider : List.of("google", "github")) {
            mockMvc.perform(unlink(provider).with(authentication(user))).andExpect(status().isNoContent());
        }

        mockMvc.perform(unlink("google").with(authentication(user))).andExpect(status().isTooManyRequests());
    }

    private static RequestPostProcessor from(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    private static MockHttpServletRequestBuilder login(String ip, String email) {
        return post("/api/auth/login")
                .with(from(ip))
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"%s","password":"secret123"}
                        """.formatted(email));
    }

    private static MockHttpServletRequestBuilder google() {
        return post("/api/auth/google")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"idToken":"id-token"}
                        """);
    }

    private static MockHttpServletRequestBuilder unlink(String provider) {
        return post("/api/auth/" + provider + "/unlink")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}");
    }
}
