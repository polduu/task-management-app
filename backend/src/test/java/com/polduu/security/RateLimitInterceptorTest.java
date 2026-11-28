package com.polduu.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerMapping;

import com.polduu.exception.TooManyRequestsException;

class RateLimitInterceptorTest {

    private static final Instant NOW = Instant.parse("2026-11-28T12:00:00Z");

    private final Clock clock = mock(Clock.class);
    private final RateLimitInterceptor interceptor =
            new RateLimitInterceptor(new RateLimiter(clock, Duration.ofMinutes(1), 1), 1, 1, 1);

    @Test
    void limitResetsWhenTheWindowEnds() {
        when(clock.instant()).thenReturn(NOW);
        assertThat(request("POST")).isTrue();
        assertThatThrownBy(() -> request("POST")).isInstanceOf(TooManyRequestsException.class);

        when(clock.instant()).thenReturn(NOW.plusSeconds(60));
        assertThat(request("POST")).isTrue();
    }

    @Test
    void preflightsAreNotCounted() {
        assertThat(request("OPTIONS")).isTrue();
        assertThat(request("OPTIONS")).isTrue();
    }

    private boolean request(String method) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/api/auth/login");
        request.setAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, "/api/auth/login");
        return interceptor.preHandle(request, new MockHttpServletResponse(), new Object());
    }
}
