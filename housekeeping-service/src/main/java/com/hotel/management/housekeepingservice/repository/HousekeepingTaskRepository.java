package com.hotel.management.housekeepingservice.repository;

import com.hotel.management.housekeepingservice.entity.HousekeepingTask;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.time.LocalDate;
import java.util.Collection;
import java.util.List;

public interface HousekeepingTaskRepository extends JpaRepository<HousekeepingTask, Long>, JpaSpecificationExecutor<HousekeepingTask> {

    List<HousekeepingTask> findByRoomId(Long roomId);

    List<HousekeepingTask> findByAssignedAgentId(Long agentId);

    List<HousekeepingTask> findByScheduledDate(LocalDate scheduledDate);

    List<HousekeepingTask> findByStatus(HousekeepingTaskStatus status);

    boolean existsByRoomIdAndStatusIn(Long roomId, Collection<HousekeepingTaskStatus> statuses);

    long count();

    long countByStatus(HousekeepingTaskStatus status);

    long countByPriority(com.hotel.management.housekeepingservice.entity.Priority priority);

    long countByAssignedAgentIdIsNull();
}
