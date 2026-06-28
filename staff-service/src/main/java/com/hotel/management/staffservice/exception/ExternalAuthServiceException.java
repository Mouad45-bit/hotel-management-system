package com.hotel.management.staffservice.exception;

import org.springframework.http.HttpStatus;

public class ExternalAuthServiceException extends RuntimeException {

    private final HttpStatus status;
    private final String error;

    public ExternalAuthServiceException(String message) {
        super(message);
        this.status = HttpStatus.BAD_REQUEST;
        this.error = "AUTH_USER_CREATION_FAILED";
    }

    public ExternalAuthServiceException(HttpStatus status, String error, String message) {
        super(message);
        this.status = status;
        this.error = error;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }
}
