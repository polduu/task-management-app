package com.polduu.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import com.polduu.service.RefreshTokenService;

import io.jsonwebtoken.JwtException;

class JwtAuthenticationFilterTest {

    private final JwtService jwtService = mock(JwtService.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtService, refreshTokenService);

    private final UUID userId = UUID.randomUUID();
    private final UUID sessionId = UUID.randomUUID();

    @BeforeEach
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void withTokenOfActiveSession_authenticatesTheUser() throws Exception {
        when(jwtService.parseAccessToken("token")).thenReturn(new JwtService.AccessToken(userId, sessionId));
        when(refreshTokenService.isSessionActive(sessionId)).thenReturn(true);

        MockFilterChain chain = run("Bearer token");

        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(userId);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void withTokenOfClosedSession_doesNotAuthenticate_butContinuesTheChain() throws Exception {
        when(jwtService.parseAccessToken("token")).thenReturn(new JwtService.AccessToken(userId, sessionId));
        when(refreshTokenService.isSessionActive(sessionId)).thenReturn(false);

        MockFilterChain chain = run("Bearer token");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void withInvalidToken_doesNotAuthenticate() throws Exception {
        when(jwtService.parseAccessToken("token")).thenThrow(new JwtException("expired"));

        run("Bearer token");

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void withoutAuthorizationHeader_doesNotTouchTheSessionStore() throws Exception {
        run(null);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(jwtService, refreshTokenService);
    }

    private MockFilterChain run(String authorization) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        return chain;
    }
}
