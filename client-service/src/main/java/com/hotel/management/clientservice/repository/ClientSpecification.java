package com.hotel.management.clientservice.repository;

import com.hotel.management.clientservice.entity.Client;
import org.springframework.data.jpa.domain.Specification;

public class ClientSpecification {

    public static Specification<Client> withFilters(String search, Boolean active) {
        return (root, query, cb) -> {
            var predicates = cb.conjunction();

            Boolean effectiveActive = (active != null) ? active : Boolean.TRUE;
            predicates = cb.and(predicates, cb.equal(root.get("active"), effectiveActive));

            if (search != null && !search.isBlank()) {
                String pattern = "%" + search.toLowerCase() + "%";
                predicates = cb.and(predicates, cb.or(
                    cb.like(cb.lower(root.get("firstName")), pattern),
                    cb.like(cb.lower(root.get("lastName")), pattern),
                    cb.like(cb.lower(cb.coalesce(root.get("email"), "")), pattern),
                    cb.like(cb.coalesce(root.get("cin"), ""), pattern),
                    cb.like(cb.coalesce(root.get("phone"), ""), pattern)
                ));
            }

            return predicates;
        };
    }
}
