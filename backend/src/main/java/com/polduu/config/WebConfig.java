package com.polduu.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.polduu.security.RateLimitInterceptor;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final RateLimitInterceptor rateLimitInterceptor;

    public WebConfig(RateLimitInterceptor rateLimitInterceptor) {
        this.rateLimitInterceptor = rateLimitInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(rateLimitInterceptor).addPathPatterns(
                "/api/auth/register",
                "/api/auth/login",
                "/api/auth/google",
                "/api/auth/github",
                "/api/auth/google/link",
                "/api/auth/google/unlink",
                "/api/auth/github/link",
                "/api/auth/github/unlink");
    }
}
