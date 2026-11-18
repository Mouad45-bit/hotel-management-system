package com.hotel.management.staffservice.exception;

public class AuthUserAlreadyLinkedException extends RuntimeException {

    public AuthUserAlreadyLinkedException(String message) {
        super(message);
    }
}
