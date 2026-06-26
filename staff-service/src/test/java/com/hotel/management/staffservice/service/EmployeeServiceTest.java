package com.hotel.management.staffservice.service;

import com.hotel.management.staffservice.dto.CreateEmployeeRequest;
import com.hotel.management.staffservice.dto.LinkAuthUserRequest;
import com.hotel.management.staffservice.dto.UpdateEmployeeRequest;
import com.hotel.management.staffservice.entity.Department;
import com.hotel.management.staffservice.entity.Employee;
import com.hotel.management.staffservice.exception.AuthUserAlreadyLinkedException;
import com.hotel.management.staffservice.exception.EmployeeCinAlreadyExistsException;
import com.hotel.management.staffservice.exception.EmployeeEmailAlreadyExistsException;
import com.hotel.management.staffservice.mapper.EmployeeMapper;
import com.hotel.management.staffservice.repository.EmployeeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EmployeeServiceTest {

    @Mock
    private EmployeeRepository employeeRepository;

    private EmployeeService service;

    @BeforeEach
    void setUp() {
        service = new EmployeeService(employeeRepository, new EmployeeMapper());
    }

    @Test
    void createCreatesActiveEmployee() {
        mockSave();

        var response = service.create(new CreateEmployeeRequest(
                "Nadia",
                "El Amrani",
                "nadia@hotel.local",
                "+212600111201",
                "BK120450",
                Department.HOUSEKEEPING
        ));

        assertThat(response.id()).isEqualTo(1L);
        assertThat(response.fullName()).isEqualTo("Nadia El Amrani");
        assertThat(response.department()).isEqualTo(Department.HOUSEKEEPING);
        assertThat(response.active()).isTrue();
        assertThat(response.authUserId()).isNull();
    }

    @Test
    void createRejectsDuplicateCin() {
        when(employeeRepository.existsByCinIgnoreCase("BK120450")).thenReturn(true);

        assertThatThrownBy(() -> service.create(new CreateEmployeeRequest(
                "Nadia",
                "El Amrani",
                null,
                null,
                "BK120450",
                Department.HOUSEKEEPING
        ))).isInstanceOf(EmployeeCinAlreadyExistsException.class)
                .hasMessageContaining("CIN");

        verify(employeeRepository, never()).save(any(Employee.class));
    }

    @Test
    void updateRejectsDuplicateEmail() {
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(activeEmployee()));
        when(employeeRepository.existsByEmailIgnoreCaseAndIdNot("used@hotel.local", 1L)).thenReturn(true);

        assertThatThrownBy(() -> service.update(1L, new UpdateEmployeeRequest(
                "Nadia",
                "El Amrani",
                "used@hotel.local",
                null,
                "BK120450",
                Department.RECEPTION
        ))).isInstanceOf(EmployeeEmailAlreadyExistsException.class)
                .hasMessageContaining("email");

        verify(employeeRepository, never()).save(any(Employee.class));
    }

    @Test
    void deactivateIsIdempotent() {
        Employee employee = activeEmployee();
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(employee));
        mockSave();

        var response = service.deactivate(1L);

        assertThat(response.active()).isFalse();
    }

    @Test
    void linkAuthUserLinksAvailableUser() {
        Employee employee = activeEmployee();
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(employee));
        when(employeeRepository.findByAuthUserId(42L)).thenReturn(Optional.empty());
        mockSave();

        var response = service.linkAuthUser(1L, new LinkAuthUserRequest(42L));

        assertThat(response.authUserId()).isEqualTo(42L);
    }

    @Test
    void linkAuthUserRejectsEmployeeLinkedToAnotherUser() {
        Employee employee = activeEmployee();
        employee.setAuthUserId(41L);
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(employee));

        assertThatThrownBy(() -> service.linkAuthUser(1L, new LinkAuthUserRequest(42L)))
                .isInstanceOf(AuthUserAlreadyLinkedException.class)
                .hasMessageContaining("Employee is already linked");

        verify(employeeRepository, never()).findByAuthUserId(42L);
        verify(employeeRepository, never()).save(any(Employee.class));
    }

    @Test
    void linkAuthUserRejectsUserLinkedToAnotherEmployee() {
        Employee employee = activeEmployee();
        Employee otherEmployee = activeEmployee();
        otherEmployee.setId(2L);
        otherEmployee.setCin("AB884210");
        otherEmployee.setAuthUserId(42L);

        when(employeeRepository.findById(1L)).thenReturn(Optional.of(employee));
        when(employeeRepository.findByAuthUserId(42L)).thenReturn(Optional.of(otherEmployee));

        assertThatThrownBy(() -> service.linkAuthUser(1L, new LinkAuthUserRequest(42L)))
                .isInstanceOf(AuthUserAlreadyLinkedException.class)
                .hasMessageContaining("Auth user is already linked");

        verify(employeeRepository, never()).save(any(Employee.class));
    }

    @Test
    void unlinkAuthUserIsIdempotent() {
        Employee employee = activeEmployee();
        employee.setAuthUserId(null);
        when(employeeRepository.findById(1L)).thenReturn(Optional.of(employee));
        mockSave();

        var response = service.unlinkAuthUser(1L);

        assertThat(response.authUserId()).isNull();
    }

    private void mockSave() {
        when(employeeRepository.save(any(Employee.class))).thenAnswer(invocation -> {
            Employee employee = invocation.getArgument(0);
            if (employee.getId() == null) {
                employee.setId(1L);
            }
            if (employee.getCreatedAt() == null) {
                employee.setCreatedAt(LocalDateTime.now());
            }
            employee.setUpdatedAt(LocalDateTime.now());
            return employee;
        });
    }

    private Employee activeEmployee() {
        Employee employee = new Employee();
        employee.setId(1L);
        employee.setFirstName("Nadia");
        employee.setLastName("El Amrani");
        employee.setEmail("nadia@hotel.local");
        employee.setPhone("+212600111201");
        employee.setCin("BK120450");
        employee.setDepartment(Department.HOUSEKEEPING);
        employee.setActive(true);
        employee.setCreatedAt(LocalDateTime.now().minusDays(5));
        employee.setUpdatedAt(LocalDateTime.now().minusDays(1));
        return employee;
    }
}
