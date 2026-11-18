package com.hotel.management.staffservice.repository;

import com.hotel.management.staffservice.entity.Department;
import com.hotel.management.staffservice.entity.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;
import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Long>, JpaSpecificationExecutor<Employee> {

    boolean existsByCinIgnoreCase(String cin);

    boolean existsByCinIgnoreCaseAndIdNot(String cin, Long id);

    boolean existsByEmailIgnoreCase(String email);

    boolean existsByEmailIgnoreCaseAndIdNot(String email, Long id);

    Optional<Employee> findByAuthUserId(Long authUserId);

    List<Employee> findByDepartmentAndDeletedFalse(Department department);
    List<Employee> findByDepartmentAndActiveAndDeletedFalse(Department department, Boolean active);
}
