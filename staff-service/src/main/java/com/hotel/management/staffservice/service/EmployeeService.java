package com.hotel.management.staffservice.service;

import com.hotel.management.staffservice.dto.CreateEmployeeRequest;
import com.hotel.management.staffservice.dto.EmployeeResponse;
import com.hotel.management.staffservice.dto.LinkAuthUserRequest;
import com.hotel.management.staffservice.dto.PageResponse;
import com.hotel.management.staffservice.dto.UpdateEmployeeRequest;
import com.hotel.management.staffservice.entity.Department;
import com.hotel.management.staffservice.entity.Employee;
import com.hotel.management.staffservice.exception.AuthUserAlreadyLinkedException;
import com.hotel.management.staffservice.exception.EmployeeCinAlreadyExistsException;
import com.hotel.management.staffservice.exception.EmployeeEmailAlreadyExistsException;
import com.hotel.management.staffservice.exception.EmployeeNotFoundException;
import com.hotel.management.staffservice.mapper.EmployeeMapper;
import com.hotel.management.staffservice.repository.EmployeeRepository;
import com.hotel.management.staffservice.service.client.AuthUserClient;
import jakarta.persistence.criteria.Predicate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final EmployeeMapper employeeMapper;
    private final AuthUserClient authUserClient;

    public EmployeeService(EmployeeRepository employeeRepository, EmployeeMapper employeeMapper) {
        this(employeeRepository, employeeMapper, null);
    }

    @Autowired
    public EmployeeService(EmployeeRepository employeeRepository, EmployeeMapper employeeMapper, AuthUserClient authUserClient) {
        this.employeeRepository = employeeRepository;
        this.employeeMapper = employeeMapper;
        this.authUserClient = authUserClient;
    }

    @Transactional
    public EmployeeResponse create(CreateEmployeeRequest request) {
        return create(request, null);
    }

    @Transactional
    public EmployeeResponse create(CreateEmployeeRequest request, String authorizationHeader) {
        assertUniqueCin(cleanRequired(request.cin()), null);
        assertUniqueEmail(cleanOptional(request.email()), null);

        Employee employee = employeeMapper.toEntity(request);
        employee.setActive(true);

        if (request.systemAccount() == null) {
            return employeeMapper.toResponse(employeeRepository.save(employee));
        }

        if (authUserClient == null) {
            throw new IllegalStateException("Auth user client is not configured");
        }

        Long createdAuthUserId = null;
        try {
            Employee savedEmployee = employeeRepository.saveAndFlush(employee);
            createdAuthUserId = authUserClient.createUser(authorizationHeader, request).id();
            savedEmployee.setAuthUserId(createdAuthUserId);
            return employeeMapper.toResponse(employeeRepository.saveAndFlush(savedEmployee));
        } catch (RuntimeException exception) {
            if (createdAuthUserId != null) {
                deactivateCreatedAuthUser(authorizationHeader, createdAuthUserId);
            }
            throw exception;
        }
    }

    @Transactional(readOnly = true)
    public PageResponse<EmployeeResponse> findAll(String keyword, Department department, Boolean active, int page, int size, String sort) {
        Pageable pageable = PageRequest.of(normalizePage(page), normalizeSize(size), parseSort(sort));
        Page<EmployeeResponse> employees = employeeRepository.findAll(buildSpecification(keyword, department, active), pageable)
                .map(employeeMapper::toResponse);

        return new PageResponse<>(
                employees.getContent(),
                employees.getNumber(),
                employees.getSize(),
                employees.getTotalElements(),
                employees.getTotalPages(),
                employees.isLast()
        );
    }

    @Transactional(readOnly = true)
    public EmployeeResponse findById(Long id) {
        return employeeMapper.toResponse(getEmployeeEntity(id));
    }

    @Transactional
    public EmployeeResponse update(Long id, UpdateEmployeeRequest request) {
        Employee employee = getEmployeeEntity(id);
        assertUniqueCin(cleanRequired(request.cin()), id);
        assertUniqueEmail(cleanOptional(request.email()), id);

        employeeMapper.applyUpdate(request, employee);
        return employeeMapper.toResponse(employeeRepository.save(employee));
    }

    @Transactional
    public void delete(Long id) {
        Employee employee = getEmployeeEntity(id);
        employee.setActive(false);
        employee.setDeleted(true);
        employeeRepository.save(employee);
    }

    @Transactional
    public EmployeeResponse activate(Long id) {
        Employee employee = getEmployeeEntity(id);
        employee.setActive(true);
        return employeeMapper.toResponse(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse deactivate(Long id) {
        Employee employee = getEmployeeEntity(id);
        employee.setActive(false);
        return employeeMapper.toResponse(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse linkAuthUser(Long id, LinkAuthUserRequest request) {
        Employee employee = getEmployeeEntity(id);
        Long userId = request.userId();

        if (employee.getAuthUserId() != null && !employee.getAuthUserId().equals(userId)) {
            throw new AuthUserAlreadyLinkedException("Employee is already linked to another auth user");
        }

        employeeRepository.findByAuthUserId(userId)
                .filter(linkedEmployee -> !linkedEmployee.getId().equals(id))
                .ifPresent(linkedEmployee -> {
                    throw new AuthUserAlreadyLinkedException("Auth user is already linked to another employee");
                });

        employee.setAuthUserId(userId);
        return employeeMapper.toResponse(employeeRepository.save(employee));
    }

    @Transactional
    public EmployeeResponse unlinkAuthUser(Long id) {
        Employee employee = getEmployeeEntity(id);
        employee.setAuthUserId(null);
        return employeeMapper.toResponse(employeeRepository.save(employee));
    }

    @Transactional(readOnly = true)
    public List<EmployeeResponse> findByDepartment(Department department, Boolean active) {
        List<Employee> employees = active == null
                ? employeeRepository.findByDepartmentAndDeletedFalse(department)
                : employeeRepository.findByDepartmentAndActiveAndDeletedFalse(department, active);

        return employees.stream()
                .map(employeeMapper::toResponse)
                .toList();
    }

    private Employee getEmployeeEntity(Long id) {
        return employeeRepository.findById(id)
                .filter(employee -> !Boolean.TRUE.equals(employee.getDeleted()))
                .orElseThrow(() -> new EmployeeNotFoundException("Employee not found with id: " + id));
    }

    private void assertUniqueCin(String cin, Long employeeId) {
        boolean exists = employeeId == null
                ? employeeRepository.existsByCinIgnoreCase(cin)
                : employeeRepository.existsByCinIgnoreCaseAndIdNot(cin, employeeId);

        if (exists) {
            throw new EmployeeCinAlreadyExistsException("Employee already exists with CIN: " + cin);
        }
    }

    private void assertUniqueEmail(String email, Long employeeId) {
        if (email == null) {
            return;
        }

        boolean exists = employeeId == null
                ? employeeRepository.existsByEmailIgnoreCase(email)
                : employeeRepository.existsByEmailIgnoreCaseAndIdNot(email, employeeId);

        if (exists) {
            throw new EmployeeEmailAlreadyExistsException("Employee already exists with email: " + email);
        }
    }

    private Specification<Employee> buildSpecification(String keyword, Department department, Boolean active) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (keyword != null && !keyword.isBlank()) {
                String pattern = "%" + keyword.trim().toLowerCase() + "%";
                predicates.add(criteriaBuilder.or(
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("firstName")), pattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("lastName")), pattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), pattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("phone")), pattern),
                        criteriaBuilder.like(criteriaBuilder.lower(root.get("cin")), pattern)
                ));
            }
            if (department != null) {
                predicates.add(criteriaBuilder.equal(root.get("department"), department));
            }
            if (active != null) {
                predicates.add(criteriaBuilder.equal(root.get("active"), active));
            }
            predicates.add(criteriaBuilder.isFalse(root.get("deleted")));

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private int normalizePage(int page) {
        return Math.max(page, 0);
    }

    private int normalizeSize(int size) {
        if (size <= 0) {
            return 20;
        }
        return Math.min(size, 100);
    }

    private Sort parseSort(String sort) {
        if (sort == null || sort.isBlank()) {
            return Sort.by(Sort.Direction.ASC, "lastName");
        }

        String[] parts = sort.split(",");
        String property = parts[0].isBlank() ? "lastName" : parts[0];
        Sort.Direction direction = parts.length > 1 && "desc".equalsIgnoreCase(parts[1])
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;
        return Sort.by(direction, property);
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

    private void deactivateCreatedAuthUser(String authorizationHeader, Long authUserId) {
        try {
            authUserClient.deactivateUser(authorizationHeader, authUserId);
        } catch (RuntimeException ignored) {
            // The employee transaction still rolls back; best effort prevents an active orphan auth account.
        }
    }
}
