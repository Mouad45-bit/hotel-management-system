package com.hotel.management.staffservice.exception;

import java.util.Map;

public class ExternalAuthValidationException extends RuntimeException {

    private final Map<String, String> fieldErrors;

    public ExternalAuthValidationException(Map<String, String> fieldErrors) {
        super("Validation failed");
        this.fieldErrors = fieldErrors;
    }

    public Map<String, String> getFieldErrors() {
        return fieldErrors;
    }
}
