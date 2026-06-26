package com.hotel.management.reservationservice.repository;

import com.hotel.management.reservationservice.entity.Reservation;
import com.hotel.management.reservationservice.entity.ReservationStatus;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public class ReservationSpecification {

    public static Specification<Reservation> withFilters(
            Long roomId, Long clientId, String status, Boolean active
    ) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (roomId != null) {
                predicates.add(cb.equal(root.get("roomId"), roomId));
            }
            if (clientId != null) {
                predicates.add(cb.equal(root.get("clientId"), clientId));
            }
            if (status != null) {
                try {
                    predicates.add(cb.equal(root.get("status"), ReservationStatus.valueOf(status.toUpperCase())));
                } catch (IllegalArgumentException ignored) {}
            }
            if (active != null) {
                predicates.add(cb.equal(root.get("active"), active));
            } else {
                predicates.add(cb.equal(root.get("active"), true));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
