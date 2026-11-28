package com.polduu.exception;

import java.time.Duration;

import lombok.Getter;

@Getter
public class TooManyRequestsException extends RuntimeException {

    private final Duration retryAfter;

    public TooManyRequestsException(Duration retryAfter) {
        super("Too many requests, try again later");
        this.retryAfter = retryAfter;
    }
}
