package com.hotel.management.roomservice.repository;

import com.hotel.management.roomservice.entity.Room;
import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public class RoomSpecification {

    private RoomSpecification() {}

    public static Specification<Room> withFilters(
            String number, RoomType type, RoomStatus status,
            Integer floor, Integer capacity, Boolean active) {

        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("active"), active));

            if (number != null)   predicates.add(cb.equal(root.get("number"), number));
            if (type != null)     predicates.add(cb.equal(root.get("type"), type));
            if (status != null)   predicates.add(cb.equal(root.get("status"), status));
            if (floor != null)    predicates.add(cb.equal(root.get("floor"), floor));
            if (capacity != null) predicates.add(cb.greaterThanOrEqualTo(root.get("capacity"), capacity));

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}