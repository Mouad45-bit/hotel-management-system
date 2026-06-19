package com.hotel.management.housekeepingservice.service;

import com.hotel.management.housekeepingservice.dto.CreateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.HousekeepingStatsResponse;
import com.hotel.management.housekeepingservice.dto.HousekeepingTaskResponse;
import com.hotel.management.housekeepingservice.dto.PageResponse;
import com.hotel.management.housekeepingservice.dto.UpdateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.external.RoomSummaryResponse;
import com.hotel.management.housekeepingservice.dto.external.StaffSummaryResponse;
import com.hotel.management.housekeepingservice.entity.HousekeepingTask;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import com.hotel.management.housekeepingservice.mapper.HousekeepingTaskMapper;
import com.hotel.management.housekeepingservice.repository.HousekeepingTaskRepository;
import com.hotel.management.housekeepingservice.service.client.RoomClient;
import com.hotel.management.housekeepingservice.service.client.StaffClient;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Service
public class HousekeepingTaskService {

    private final HousekeepingTaskRepository housekeepingTaskRepository;
    private final HousekeepingTaskMapper housekeepingTaskMapper;
    private final RoomClient roomClient;
    private final StaffClient staffClient;

    public HousekeepingTaskService(
            HousekeepingTaskRepository housekeepingTaskRepository,
            HousekeepingTaskMapper housekeepingTaskMapper,
            RoomClient roomClient,
            StaffClient staffClient
    ) {
        this.housekeepingTaskRepository = housekeepingTaskRepository;
        this.housekeepingTaskMapper = housekeepingTaskMapper;
        this.roomClient = roomClient;
        this.staffClient = staffClient;
    }

    @Transactional
    public HousekeepingTaskResponse createTask(CreateHousekeepingTaskRequest request) {
        RoomSummaryResponse room = roomClient.findSummaryById(request.roomId());
        if (!room.active()) {
            throw new IllegalStateException("Room is not active: " + request.roomId());
        }

        HousekeepingTask task = housekeepingTaskMapper.toEntity(request);
        task.setRoomNumber(room.roomNumber());

        if (request.assignedAgentId() != null) {
            StaffSummaryResponse staff = staffClient.findSummaryById(request.assignedAgentId());
            if (!staff.active()) {
                throw new IllegalStateException("Assigned agent is not active: " + request.assignedAgentId());
            }
            task.setAssignedAgentId(staff.employeeId());
            task.setAssignedAgentName(staff.fullName());
        }

        return housekeepingTaskMapper.toResponse(housekeepingTaskRepository.save(task));
    }

    @Transactional
    public HousekeepingTaskResponse updateTask(Long id, UpdateHousekeepingTaskRequest request) {
        HousekeepingTask task = getTaskEntity(id);
        requireNotFinal(task, "Cannot modify a final housekeeping task");
        housekeepingTaskMapper.applyUpdate(request, task);
        return housekeepingTaskMapper.toResponse(housekeepingTaskRepository.save(task));
    }

    @Transactional(readOnly = true)
    public HousekeepingTaskResponse getTaskById(Long id) {
        return housekeepingTaskMapper.toResponse(getTaskEntity(id));
    }

    @Transactional(readOnly = true)
    public PageResponse<HousekeepingTaskResponse> getTasks(
            HousekeepingTaskStatus status,
            HousekeepingTaskType type,
            Priority priority,
            Long roomId,
            Long agentId,
            LocalDate scheduledDate,
            LocalDate from,
            LocalDate to,
            int page,
            int size,
            String sort
    ) {
        Pageable pageable = PageRequest.of(normalizePage(page), normalizeSize(size), parseSort(sort));
        Page<HousekeepingTaskResponse> tasks = housekeepingTaskRepository.findAll(
                buildSpecification(status, type, priority, roomId, agentId, scheduledDate, from, to),
                pageable
        ).map(housekeepingTaskMapper::toResponse);

        return new PageResponse<>(
                tasks.getContent(),
                tasks.getNumber(),
                tasks.getSize(),
                tasks.getTotalElements(),
                tasks.getTotalPages(),
                tasks.isLast()
        );
    }

    @Transactional(readOnly = true)
    public List<HousekeepingTaskResponse> getTasksByRoomId(Long roomId) {
        return housekeepingTaskRepository.findByRoomId(roomId)
                .stream()
                .sorted((first, second) -> second.getScheduledDate().compareTo(first.getScheduledDate()))
                .map(housekeepingTaskMapper::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<HousekeepingTaskResponse> getTasksByAgentId(Long agentId) {
        return housekeepingTaskRepository.findByAssignedAgentId(agentId)
                .stream()
                .sorted((first, second) -> first.getScheduledDate().compareTo(second.getScheduledDate()))
                .map(housekeepingTaskMapper::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<HousekeepingTaskResponse> getTodayTasks() {
        return housekeepingTaskRepository.findByScheduledDate(LocalDate.now())
                .stream()
                .map(housekeepingTaskMapper::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public HousekeepingStatsResponse getStats() {
        List<HousekeepingTask> tasks = housekeepingTaskRepository.findAll();
        return new HousekeepingStatsResponse(
                tasks.size(),
                countStatus(tasks, HousekeepingTaskStatus.TODO),
                countStatus(tasks, HousekeepingTaskStatus.IN_PROGRESS),
                countStatus(tasks, HousekeepingTaskStatus.DONE),
                countStatus(tasks, HousekeepingTaskStatus.CANCELLED),
                tasks.stream().filter(task -> task.getPriority() == Priority.URGENT).count(),
                tasks.stream().filter(task -> task.getAssignedAgentId() == null).count()
        );
    }

    private HousekeepingTask getTaskEntity(Long id) {
        return housekeepingTaskRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Housekeeping task not found with id: " + id));
    }

    private void requireNotFinal(HousekeepingTask task, String message) {
        if (task.getStatus() == HousekeepingTaskStatus.DONE || task.getStatus() == HousekeepingTaskStatus.CANCELLED) {
            throw new IllegalStateException(message);
        }
    }

    private long countStatus(List<HousekeepingTask> tasks, HousekeepingTaskStatus status) {
        return tasks.stream().filter(task -> task.getStatus() == status).count();
    }

    private Specification<HousekeepingTask> buildSpecification(
            HousekeepingTaskStatus status,
            HousekeepingTaskType type,
            Priority priority,
            Long roomId,
            Long agentId,
            LocalDate scheduledDate,
            LocalDate from,
            LocalDate to
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (status != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), status));
            }
            if (type != null) {
                predicates.add(criteriaBuilder.equal(root.get("type"), type));
            }
            if (priority != null) {
                predicates.add(criteriaBuilder.equal(root.get("priority"), priority));
            }
            if (roomId != null) {
                predicates.add(criteriaBuilder.equal(root.get("roomId"), roomId));
            }
            if (agentId != null) {
                predicates.add(criteriaBuilder.equal(root.get("assignedAgentId"), agentId));
            }
            if (scheduledDate != null) {
                predicates.add(criteriaBuilder.equal(root.get("scheduledDate"), scheduledDate));
            }
            if (from != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("scheduledDate"), from));
            }
            if (to != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("scheduledDate"), to));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private int normalizePage(int page) {
        return Math.max(page, 0);
    }

    private int normalizeSize(int size) {
        if (size <= 0) {
            return 10;
        }
        return Math.min(size, 100);
    }

    private Sort parseSort(String sort) {
        if (sort == null || sort.isBlank()) {
            return Sort.by(Sort.Direction.ASC, "scheduledDate");
        }

        String[] parts = sort.split(",");
        String property = parts[0].isBlank() ? "scheduledDate" : parts[0];
        Sort.Direction direction = parts.length > 1 && "desc".equalsIgnoreCase(parts[1])
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;
        return Sort.by(direction, property);
    }
}
