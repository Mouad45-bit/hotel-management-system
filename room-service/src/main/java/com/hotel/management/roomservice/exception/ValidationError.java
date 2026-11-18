package com.hotel.management.roomservice.exception;

import java.time.LocalDateTime;
import java.util.Map;

public record ValidationError(
    LocalDateTime timestamp,
    int status,
    String error,
    String message,
    String path,
    Map<String, String> fieldErrors
) {
}
