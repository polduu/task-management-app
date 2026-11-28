package com.polduu.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Limits per user or per IP, before the body is read. The per-IP limits are generous because a
 * whole office can share one address; login adds a strict limit per IP and email.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final RateLimiter rateLimiter;
    private final int loginPerIp;
    private final int publicPerIp;
    private final int accountPerUser;

    public RateLimitInterceptor(RateLimiter rateLimiter,
            @Value("${rate-limit.login-per-ip:100}") int loginPerIp,
            @Value("${rate-limit.public-per-ip:30}") int publicPerIp,
            @Value("${rate-limit.account-per-user:10}") int accountPerUser) {
        this.rateLimiter = rateLimiter;
        this.loginPerIp = loginPerIp;
        this.publicPerIp = publicPerIp;
        this.accountPerUser = accountPerUser;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // CORS preflights don't count
        if (!"POST".equals(request.getMethod())) {
            return true;
        }
        // The matched route, not the raw URL: an encoded path must not get its own counter
        String route = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
        if (route.endsWith("/link") || route.endsWith("/unlink")) {
            // Private routes: one budget across account changes, whatever IP they come from
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            rateLimiter.check("user:" + authentication.getPrincipal(), accountPerUser);
        } else {
            // Public routes count by IP even if a token is sent
            rateLimiter.check("ip:" + request.getRemoteAddr() + ":" + route,
                    route.endsWith("/login") ? loginPerIp : publicPerIp);
        }
        return true;
    }
}
