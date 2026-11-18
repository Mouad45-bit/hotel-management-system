package com.hotel.management.clientservice.repository;

import com.hotel.management.clientservice.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<Client, Long>, JpaSpecificationExecutor<Client> {

    boolean existsByEmail(String email);
    boolean existsByCin(String cin);
    boolean existsByPassportNumber(String passportNumber);

    boolean existsByEmailAndIdNot(String email, Long id);
    boolean existsByCinAndIdNot(String cin, Long id);
    boolean existsByPassportNumberAndIdNot(String passportNumber, Long id);

    Optional<Client> findByEmail(String email);

    List<Client> findByActiveFalse();
    List<Client> findByActiveTrue();

    @Query("SELECT c FROM Client c WHERE c.active = true AND (" +
           "LOWER(c.firstName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(c.lastName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(c.email) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "c.cin LIKE CONCAT('%', :keyword, '%') OR " +
           "c.phone LIKE CONCAT('%', :keyword, '%'))")
    List<Client> search(@Param("keyword") String keyword);
}
