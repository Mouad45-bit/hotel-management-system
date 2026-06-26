package com.hotel.management.staffservice.exception;

public class EmployeeEmailAlreadyExistsException extends RuntimeException {

    public EmployeeEmailAlreadyExistsException(String message) {
        super(message);
    }
}
