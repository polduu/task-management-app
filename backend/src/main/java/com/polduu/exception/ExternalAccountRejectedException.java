package com.polduu.exception;

public class ExternalAccountRejectedException extends RuntimeException {
    public ExternalAccountRejectedException() {
        super("The external account could not be verified");
    }
}
