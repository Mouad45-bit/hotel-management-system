package com.hotel.management.housekeepingservice.mapper;

import com.hotel.management.housekeepingservice.dto.CreateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.HousekeepingTaskResponse;
import com.hotel.management.housekeepingservice.dto.UpdateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.entity.HousekeepingTask;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import org.springframework.stereotype.Component;

@Component
public class HousekeepingTaskMapper {

    public HousekeepingTask toEntity(CreateHousekeepingTaskRequest request) {
        HousekeepingTask task = new HousekeepingTask();
        task.setRoomId(request.roomId());
        task.setReservationId(request.reservationId());
        task.setAssignedAgentId(request.assignedAgentId());
        task.setType(request.type());
        task.setStatus(HousekeepingTaskStatus.TODO);
        task.setPriority(request.priority());
        task.setScheduledDate(request.scheduledDate());
        task.setNotes(request.notes());
        return task;
    }

    public void applyUpdate(UpdateHousekeepingTaskRequest request, HousekeepingTask task) {
        task.setType(request.type());
        task.setPriority(request.priority());
        task.setScheduledDate(request.scheduledDate());
        task.setNotes(request.notes());
    }

    public HousekeepingTaskResponse toResponse(HousekeepingTask task) {
        return new HousekeepingTaskResponse(
                task.getId(),
                task.getRoomId(),
                task.getRoomNumber(),
                task.getReservationId(),
                task.getAssignedAgentId(),
                task.getAssignedAgentName(),
                task.getType(),
                task.getStatus(),
                task.getPriority(),
                task.getScheduledDate(),
                task.getStartedAt(),
                task.getCompletedAt(),
                task.getCancelledAt(),
                task.getCancellationReason(),
                task.getNotes(),
                task.getCreatedAt(),
                task.getUpdatedAt()
        );
    }
}
