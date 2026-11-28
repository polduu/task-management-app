package com.polduu.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import com.polduu.exception.InvalidCredentialsException;

import lombok.extern.slf4j.Slf4j;

/** Calls to GitHub's OAuth and REST APIs. Tokens and codes are never logged. */
@Slf4j
@Component
public class GitHubClient {

    private static final String TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String USER_URL = "https://api.github.com/user";
    private static final String EMAILS_URL = "https://api.github.com/user/emails";

    private final RestClient restClient;
    private final String clientId;
    private final String clientSecret;

    public GitHubClient(RestClient githubRestClient,
            @Value("${github.client-id}") String clientId,
            @Value("${github.client-secret}") String clientSecret) {
        this.restClient = githubRestClient;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public record Profile(String id, String name) {}

    // GitHub answers 200 with an error field for a bad code, so a 4xx here is a real failure
    public String exchangeCode(String code) {
        Map<String, Object> response = restClient.post()
                .uri(TOKEN_URL)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("client_id", clientId, "client_secret", clientSecret, "code", code))
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});

        if (response == null || !(response.get("access_token") instanceof String accessToken)) {
            log.warn("GitHub rejected the authorization code");
            throw new InvalidCredentialsException();
        }
        return accessToken;
    }

    public Profile fetchProfile(String accessToken) {
        Map<String, Object> user = get(USER_URL, accessToken, new ParameterizedTypeReference<>() {});
        if (user == null || user.get("id") == null) {
            log.warn("GitHub returned a profile without id");
            throw new InvalidCredentialsException();
        }
        Object name = user.get("name") != null ? user.get("name") : user.get("login");
        return new Profile(String.valueOf(user.get("id")), (String) name);
    }

    public String fetchPrimaryVerifiedEmail(String accessToken) {
        List<Map<String, Object>> emails = get(EMAILS_URL, accessToken, new ParameterizedTypeReference<>() {});
        return Optional.ofNullable(emails).orElseGet(List::of).stream()
                .filter(e -> Boolean.TRUE.equals(e.get("primary"))
                        && Boolean.TRUE.equals(e.get("verified"))
                        && e.get("email") != null)
                .map(e -> e.get("email").toString())
                .findFirst()
                .orElseThrow(() -> {
                    log.warn("GitHub account has no primary verified email");
                    return new InvalidCredentialsException();
                });
    }

    // A refused token or missing scope is the caller's problem (401); rate limits and outages are not (502)
    private <T> T get(String url, String accessToken, ParameterizedTypeReference<T> type) {
        try {
            return restClient.get()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .retrieve()
                    .body(type);
        } catch (HttpClientErrorException e) {
            if (isRateLimit(e) || !isRefusal(e.getStatusCode())) {
                throw e;
            }
            log.warn("GitHub refused {} with status {}", url, e.getStatusCode().value());
            throw new InvalidCredentialsException();
        }
    }

    private static boolean isRefusal(HttpStatusCode status) {
        return status.isSameCodeAs(HttpStatus.UNAUTHORIZED)
                || status.isSameCodeAs(HttpStatus.FORBIDDEN)
                || status.isSameCodeAs(HttpStatus.NOT_FOUND);
    }

    private static boolean isRateLimit(HttpClientErrorException e) {
        HttpHeaders headers = e.getResponseHeaders();
        return e.getStatusCode().isSameCodeAs(HttpStatus.TOO_MANY_REQUESTS)
                || headers != null && ("0".equals(headers.getFirst("X-RateLimit-Remaining"))
                        || headers.getFirst(HttpHeaders.RETRY_AFTER) != null);
    }
}
