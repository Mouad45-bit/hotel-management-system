package com.hotel.management.staffservice.controller;

import com.hotel.management.staffservice.dto.CreateEmployeeRequest;
import com.hotel.management.staffservice.dto.EmployeeResponse;
import com.hotel.management.staffservice.dto.LinkAuthUserRequest;
import com.hotel.management.staffservice.dto.PageResponse;
import com.hotel.management.staffservice.dto.UpdateEmployeeRequest;
import com.hotel.management.staffservice.entity.Department;
import com.hotel.management.staffservice.service.EmployeeService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/employees")
public class EmployeeController {

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @PostMapping
    public ResponseEntity<EmployeeResponse> create(
            @Valid @RequestBody CreateEmployeeRequest request,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader
    ) {
        EmployeeResponse response = employeeService.create(request, authorizationHeader);
        return ResponseEntity
                .created(URI.create("/api/employees/" + response.id()))
                .body(response);
    }

    @GetMapping
    public PageResponse<EmployeeResponse> findAll(
            @RequestParam(required = false) String keyword,
            @RequestParam(required = false) Department department,
            @RequestParam(required = false) Boolean active,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "lastName,asc") String sort
    ) {
        return employeeService.findAll(keyword, department, active, page, size, sort);
    }

    @GetMapping("/{id}")
    public EmployeeResponse findById(@PathVariable Long id) {
        return employeeService.findById(id);
    }

    @PutMapping("/{id}")
    public EmployeeResponse update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateEmployeeRequest request
    ) {
        return employeeService.update(id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        employeeService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping("/{id}/activate")
    public EmployeeResponse activate(@PathVariable Long id) {
        return employeeService.activate(id);
    }

    @PatchMapping("/{id}/deactivate")
    public EmployeeResponse deactivate(@PathVariable Long id) {
        return employeeService.deactivate(id);
    }

    @PatchMapping("/{id}/link-user")
    public EmployeeResponse linkAuthUser(
            @PathVariable Long id,
            @Valid @RequestBody LinkAuthUserRequest request
    ) {
        return employeeService.linkAuthUser(id, request);
    }

    @PatchMapping("/{id}/unlink-user")
    public EmployeeResponse unlinkAuthUser(@PathVariable Long id) {
        return employeeService.unlinkAuthUser(id);
    }

    @GetMapping("/department/{department}")
    public List<EmployeeResponse> findByDepartment(
            @PathVariable Department department,
            @RequestParam(required = false) Boolean active
    ) {
        return employeeService.findByDepartment(department, active);
    }

    @GetMapping("/ping")
    public Map<String, String> ping() {
        return Map.of("service", "staff-service", "status", "UP");
    }
}
