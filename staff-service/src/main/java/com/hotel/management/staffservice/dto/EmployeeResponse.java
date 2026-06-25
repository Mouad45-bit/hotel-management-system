package com.hotel.management.staffservice.dto;

import com.hotel.management.staffservice.entity.Department;

import java.time.LocalDateTime;

public record EmployeeResponse(
        Long id,
        String firstName,
        String lastName,
        String fullName,
        String email,
        String phone,
        String cin,
        Department department,
        Boolean active,
        Long authUserId,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
