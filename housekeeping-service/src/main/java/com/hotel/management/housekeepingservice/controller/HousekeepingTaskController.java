package com.hotel.management.housekeepingservice.controller;

import com.hotel.management.housekeepingservice.dto.AssignHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.CancelHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.CreateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.HousekeepingStatsResponse;
import com.hotel.management.housekeepingservice.dto.HousekeepingTaskResponse;
import com.hotel.management.housekeepingservice.dto.PageResponse;
import com.hotel.management.housekeepingservice.dto.UpdateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import com.hotel.management.housekeepingservice.service.HousekeepingTaskService;
import jakarta.validation.Valid;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/housekeeping-tasks")
public class HousekeepingTaskController {

    private final HousekeepingTaskService housekeepingTaskService;

    public HousekeepingTaskController(HousekeepingTaskService housekeepingTaskService) {
        this.housekeepingTaskService = housekeepingTaskService;
    }

    @GetMapping("/ping")
    public Map<String, String> ping() {
        return Map.of("service", "housekeeping-service", "status", "UP");
    }

    @PostMapping
    public ResponseEntity<HousekeepingTaskResponse> createTask(@Valid @RequestBody CreateHousekeepingTaskRequest request) {
        HousekeepingTaskResponse response = housekeepingTaskService.createTask(request);
        return ResponseEntity
                .created(URI.create("/api/housekeeping-tasks/" + response.id()))
                .body(response);
    }

    @GetMapping
    public PageResponse<HousekeepingTaskResponse> getTasks(
            @RequestParam(required = false) HousekeepingTaskStatus status,
            @RequestParam(required = false) HousekeepingTaskType type,
            @RequestParam(required = false) Priority priority,
            @RequestParam(required = false) Long roomId,
            @RequestParam(required = false) Long agentId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate scheduledDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "scheduledDate,asc") String sort
    ) {
        return housekeepingTaskService.getTasks(status, type, priority, roomId, agentId, scheduledDate, from, to, page, size, sort);
    }

    @GetMapping("/{id}")
    public HousekeepingTaskResponse getTaskById(@PathVariable Long id) {
        return housekeepingTaskService.getTaskById(id);
    }

    @PutMapping("/{id}")
    public HousekeepingTaskResponse updateTask(
            @PathVariable Long id,
            @Valid @RequestBody UpdateHousekeepingTaskRequest request
    ) {
        return housekeepingTaskService.updateTask(id, request);
    }

    @PatchMapping("/{id}/assign")
    public HousekeepingTaskResponse assignTask(
            @PathVariable Long id,
            @Valid @RequestBody AssignHousekeepingTaskRequest request
    ) {
        return housekeepingTaskService.assignTask(id, request);
    }

    @PatchMapping("/{id}/start")
    public HousekeepingTaskResponse startTask(@PathVariable Long id) {
        return housekeepingTaskService.startTask(id);
    }

    @PatchMapping("/{id}/complete")
    public HousekeepingTaskResponse completeTask(@PathVariable Long id) {
        return housekeepingTaskService.completeTask(id);
    }

    @PatchMapping("/{id}/cancel")
    public HousekeepingTaskResponse cancelTask(
            @PathVariable Long id,
            @Valid @RequestBody CancelHousekeepingTaskRequest request
    ) {
        return housekeepingTaskService.cancelTask(id, request);
    }

    @GetMapping("/room/{roomId}")
    public List<HousekeepingTaskResponse> getTasksByRoomId(@PathVariable Long roomId) {
        return housekeepingTaskService.getTasksByRoomId(roomId);
    }

    @GetMapping("/agent/{agentId}")
    public List<HousekeepingTaskResponse> getTasksByAgentId(@PathVariable Long agentId) {
        return housekeepingTaskService.getTasksByAgentId(agentId);
    }

    @GetMapping("/today")
    public List<HousekeepingTaskResponse> getTodayTasks() {
        return housekeepingTaskService.getTodayTasks();
    }

    @GetMapping("/stats")
    public HousekeepingStatsResponse getStats() {
        return housekeepingTaskService.getStats();
    }
}
