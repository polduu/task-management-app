package com.polduu.exception;

public class ReauthenticationRequiredException extends RuntimeException {
    public ReauthenticationRequiredException(String message) {
        super(message);
    }
}
