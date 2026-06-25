package com.hotel.management.staffservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationError> handleValidation(MethodArgumentNotValidException exception, HttpServletRequest request) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        exception.getBindingResult().getFieldErrors().forEach(error ->
                fieldErrors.put(error.getField(), error.getDefaultMessage())
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ValidationError(
                LocalDateTime.now(),
                HttpStatus.BAD_REQUEST.value(),
                "VALIDATION_ERROR",
                "Validation failed",
                request.getRequestURI(),
                fieldErrors
        ));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiError> handleTypeMismatch(MethodArgumentTypeMismatchException exception, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "Invalid request parameter", request);
    }

    @ExceptionHandler(EmployeeNotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(EmployeeNotFoundException exception, HttpServletRequest request) {
        return build(HttpStatus.NOT_FOUND, "EMPLOYEE_NOT_FOUND", exception.getMessage(), request);
    }

    @ExceptionHandler(EmployeeCinAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleCinConflict(EmployeeCinAlreadyExistsException exception, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "EMPLOYEE_CIN_ALREADY_EXISTS", exception.getMessage(), request);
    }

    @ExceptionHandler(EmployeeEmailAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleEmailConflict(EmployeeEmailAlreadyExistsException exception, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "EMPLOYEE_EMAIL_ALREADY_EXISTS", exception.getMessage(), request);
    }

    @ExceptionHandler(AuthUserAlreadyLinkedException.class)
    public ResponseEntity<ApiError> handleAuthUserConflict(AuthUserAlreadyLinkedException exception, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "AUTH_USER_ALREADY_LINKED", exception.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception exception, HttpServletRequest request) {
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", "Unexpected server error", request);
    }

    private ResponseEntity<ApiError> build(HttpStatus status, String error, String message, HttpServletRequest request) {
        return ResponseEntity.status(status).body(new ApiError(
                LocalDateTime.now(),
                status.value(),
                error,
                message,
                request.getRequestURI()
        ));
    }
}
