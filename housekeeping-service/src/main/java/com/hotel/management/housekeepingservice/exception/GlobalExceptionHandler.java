package com.hotel.management.housekeepingservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
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

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiError> handleConstraintViolation(ConstraintViolationException exception, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Validation failed", request);
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class, MissingServletRequestParameterException.class})
    public ResponseEntity<ApiError> handleBadRequest(Exception exception, HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "BAD_REQUEST", "Invalid request parameter", request);
    }

    @ExceptionHandler(HousekeepingTaskNotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(HousekeepingTaskNotFoundException exception, HttpServletRequest request) {
        return build(HttpStatus.NOT_FOUND, "HOUSEKEEPING_TASK_NOT_FOUND", exception.getMessage(), request);
    }

    @ExceptionHandler(HousekeepingConflictException.class)
    public ResponseEntity<ApiError> handleConflict(HousekeepingConflictException exception, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "HOUSEKEEPING_CONFLICT", exception.getMessage(), request);
    }

    @ExceptionHandler(HousekeepingBusinessException.class)
    public ResponseEntity<ApiError> handleBusiness(HousekeepingBusinessException exception, HttpServletRequest request) {
        return build(HttpStatus.CONFLICT, "HOUSEKEEPING_BUSINESS_ERROR", exception.getMessage(), request);
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
