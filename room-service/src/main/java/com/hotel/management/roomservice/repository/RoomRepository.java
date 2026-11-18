package com.hotel.management.roomservice.repository;

import com.hotel.management.roomservice.dto.RoomStatsResponse;
import com.hotel.management.roomservice.entity.Room;
import com.hotel.management.roomservice.entity.RoomStatus;
import com.hotel.management.roomservice.entity.RoomType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoomRepository extends JpaRepository<Room, Long>, JpaSpecificationExecutor<Room> {

    boolean existsByNumber(String number);

    Optional<Room> findByNumber(String number);

    List<Room> findByActiveFalse();

    List<Room> findByActiveTrue();

    List<Room> findByStatusAndActiveTrue(RoomStatus status);

    long countByActiveTrue();

    long countByStatusAndActiveTrue(RoomStatus status);

    @Query("SELECT r FROM Room r WHERE r.active = true " +
        "AND (:number IS NULL OR r.number = :number) " +
        "AND (:type IS NULL OR r.type = :type) " +
        "AND (:status IS NULL OR r.status = :status) " +
        "AND (:floor IS NULL OR r.floor = :floor) " +
        "AND (:capacity IS NULL OR r.capacity >= :capacity)")
    List<Room> findWithFilters(@Param("number") String number,
                               @Param("type") RoomType type,
                               @Param("status") RoomStatus status,
                               @Param("floor") Integer floor,
                               @Param("capacity") Integer capacity);

    @Query("SELECT new com.hotel.management.roomservice.dto.RoomStatsResponse(" +
        "COUNT(r), " +
        "SUM(CASE WHEN r.status = 'AVAILABLE' THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN r.status = 'OCCUPIED' THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN r.status = 'RESERVED' THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN r.status = 'CLEANING' THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN r.status = 'MAINTENANCE' THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN r.status = 'OUT_OF_SERVICE' THEN 1 ELSE 0 END)) " +
        "FROM Room r WHERE r.active = true")
    RoomStatsResponse getRoomStats();
}
