package com.polduu.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.polduu.exception.TooManyRequestsException;

/**
 * Fixed-window request counters. They live in memory, so each application instance limits on its
 * own and a restart clears them.
 */
@Component
public class RateLimiter {

    private record Window(Instant start, int requests) {}

    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final Clock clock;
    private final Duration windowLength;

    private final int loginPerEmail;

    public RateLimiter(Clock clock, @Value("${rate-limit.window:1m}") Duration windowLength,
            @Value("${rate-limit.login-per-email:10}") int loginPerEmail) {
        this.clock = clock;
        this.windowLength = windowLength;
        this.loginPerEmail = loginPerEmail;
    }

    // Keyed by IP too, so nobody can lock another person out from a different network
    public void checkLogin(String ip, String email) {
        check("login:" + ip + ":" + email, loginPerEmail);
    }

    // Counts one request for the key and rejects it beyond the limit
    public void check(String key, int maxRequests) {
        Instant now = clock.instant();
        Window window = windows.compute(key, (k, current) ->
                current == null || isOver(current, now)
                        ? new Window(now, 1)
                        : new Window(current.start(), current.requests() + 1));
        if (window.requests() > maxRequests) {
            throw new TooManyRequestsException(Duration.between(now, window.start().plus(windowLength)));
        }
    }

    @Scheduled(fixedDelayString = "${rate-limit.cleanup-delay:10m}")
    public void purgeExpiredWindows() {
        Instant now = clock.instant();
        windows.values().removeIf(window -> isOver(window, now));
    }

    private boolean isOver(Window window, Instant now) {
        return !window.start().plus(windowLength).isAfter(now);
    }
}
