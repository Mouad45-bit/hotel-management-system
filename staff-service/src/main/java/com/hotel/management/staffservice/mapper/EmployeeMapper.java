package com.hotel.management.staffservice.mapper;

import com.hotel.management.staffservice.dto.CreateEmployeeRequest;
import com.hotel.management.staffservice.dto.EmployeeResponse;
import com.hotel.management.staffservice.dto.UpdateEmployeeRequest;
import com.hotel.management.staffservice.entity.Employee;
import org.springframework.stereotype.Component;

@Component
public class EmployeeMapper {

    public Employee toEntity(CreateEmployeeRequest request) {
        Employee employee = new Employee();
        employee.setFirstName(cleanRequired(request.firstName()));
        employee.setLastName(cleanRequired(request.lastName()));
        employee.setEmail(cleanOptional(request.email()));
        employee.setPhone(cleanOptional(request.phone()));
        employee.setCin(cleanRequired(request.cin()));
        employee.setDepartment(request.department());
        employee.setActive(true);
        return employee;
    }

    public void applyUpdate(UpdateEmployeeRequest request, Employee employee) {
        employee.setFirstName(cleanRequired(request.firstName()));
        employee.setLastName(cleanRequired(request.lastName()));
        employee.setEmail(cleanOptional(request.email()));
        employee.setPhone(cleanOptional(request.phone()));
        employee.setCin(cleanRequired(request.cin()));
        employee.setDepartment(request.department());
    }

    public EmployeeResponse toResponse(Employee employee) {
        return new EmployeeResponse(
                employee.getId(),
                employee.getFirstName(),
                employee.getLastName(),
                buildFullName(employee),
                employee.getEmail(),
                employee.getPhone(),
                employee.getCin(),
                employee.getDepartment(),
                employee.getActive(),
                employee.getAuthUserId(),
                employee.getCreatedAt(),
                employee.getUpdatedAt()
        );
    }

    private String buildFullName(Employee employee) {
        return "%s %s".formatted(employee.getFirstName(), employee.getLastName()).trim();
    }

    private String cleanRequired(String value) {
        return value == null ? null : value.trim();
    }

    private String cleanOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        return value.trim();
    }
}
