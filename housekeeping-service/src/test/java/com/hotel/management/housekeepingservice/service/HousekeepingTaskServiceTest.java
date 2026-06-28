package com.hotel.management.housekeepingservice.service;

import com.hotel.management.housekeepingservice.dto.AssignHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.CancelHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.CreateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.UpdateHousekeepingTaskRequest;
import com.hotel.management.housekeepingservice.dto.external.RoomSummaryResponse;
import com.hotel.management.housekeepingservice.dto.external.StaffSummaryResponse;
import com.hotel.management.housekeepingservice.entity.HousekeepingTask;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskStatus;
import com.hotel.management.housekeepingservice.entity.HousekeepingTaskType;
import com.hotel.management.housekeepingservice.entity.Priority;
import com.hotel.management.housekeepingservice.exception.HousekeepingBusinessException;
import com.hotel.management.housekeepingservice.exception.HousekeepingConflictException;
import com.hotel.management.housekeepingservice.mapper.HousekeepingTaskMapper;
import com.hotel.management.housekeepingservice.repository.HousekeepingTaskRepository;
import com.hotel.management.housekeepingservice.service.client.RoomClient;
import com.hotel.management.housekeepingservice.service.client.StaffClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HousekeepingTaskServiceTest {

    private static final LocalDate SCHEDULED_DATE = LocalDate.now().plusDays(1);

    @Mock
    private HousekeepingTaskRepository housekeepingTaskRepository;

    @Mock
    private RoomClient roomClient;

    @Mock
    private StaffClient staffClient;

    private HousekeepingTaskService service;

    @BeforeEach
    void setUp() {
        service = new HousekeepingTaskService(
                housekeepingTaskRepository,
                new HousekeepingTaskMapper(),
                roomClient,
                staffClient
        );
    }

    @Test
    void createTaskCreatesValidTask() {
        when(roomClient.findSummaryById(301L)).thenReturn(activeRoom());
        when(staffClient.findSummaryById(101L)).thenReturn(activeAgent());
        mockSave();

        var response = service.createTask(new CreateHousekeepingTaskRequest(
                301L,
                905L,
                HousekeepingTaskType.STANDARD_CLEANING,
                Priority.HIGH,
                SCHEDULED_DATE,
                101L,
                "Nettoyage après check-out"
        ));

        assertThat(response.id()).isEqualTo(1L);
        assertThat(response.roomId()).isEqualTo(301L);
        assertThat(response.roomNumber()).isEqualTo("301");
        assertThat(response.assignedAgentId()).isEqualTo(101L);
        assertThat(response.assignedAgentName()).isEqualTo("Nadia El Amrani");
        assertThat(response.status()).isEqualTo(HousekeepingTaskStatus.TODO);
    }

    @Test
    void createTaskRejectsInactiveRoom() {
        when(roomClient.findSummaryById(301L)).thenReturn(new RoomSummaryResponse(301L, "301", "MAINTENANCE", false));

        assertThatThrownBy(() -> service.createTask(new CreateHousekeepingTaskRequest(
                301L,
                null,
                HousekeepingTaskType.STANDARD_CLEANING,
                Priority.MEDIUM,
                SCHEDULED_DATE,
                null,
                null
        ))).isInstanceOf(HousekeepingBusinessException.class)
                .hasMessageContaining("Room is not active");

        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
    }

    @Test
    void createTaskRejectsInactiveAgent() {
        when(roomClient.findSummaryById(301L)).thenReturn(activeRoom());
        when(staffClient.findSummaryById(101L)).thenReturn(new StaffSummaryResponse(101L, "Nadia El Amrani", "HOUSEKEEPING", false));

        assertThatThrownBy(() -> service.createTask(new CreateHousekeepingTaskRequest(
                301L,
                null,
                HousekeepingTaskType.STANDARD_CLEANING,
                Priority.MEDIUM,
                SCHEDULED_DATE,
                101L,
                null
        ))).isInstanceOf(HousekeepingBusinessException.class)
                .hasMessageContaining("Assigned agent is not active");

        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
    }

    @Test
    void startTaskMovesTodoToInProgress() {
        HousekeepingTask task = taskWithStatus(HousekeepingTaskStatus.TODO);
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(task));
        mockSave();

        var response = service.startTask(1L);

        assertThat(response.status()).isEqualTo(HousekeepingTaskStatus.IN_PROGRESS);
        assertThat(response.startedAt()).isNotNull();
        verify(roomClient).markRoomHousekeeping(301L);
    }

    @Test
    void startTaskRejectsNonTodoTask() {
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(taskWithStatus(HousekeepingTaskStatus.IN_PROGRESS)));

        assertThatThrownBy(() -> service.startTask(1L))
                .isInstanceOf(HousekeepingConflictException.class)
                .hasMessageContaining("Only TODO housekeeping tasks can be started");

        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
        verify(roomClient, never()).markRoomHousekeeping(any());
    }

    @Test
    void completeTaskMovesInProgressToDone() {
        HousekeepingTask task = taskWithStatus(HousekeepingTaskStatus.IN_PROGRESS);
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(task));
        mockSave();

        var response = service.completeTask(1L);

        assertThat(response.status()).isEqualTo(HousekeepingTaskStatus.DONE);
        assertThat(response.completedAt()).isNotNull();
        verify(roomClient).markRoomAvailable(301L);
    }

    @Test
    void completeTaskRejectsNonInProgressTask() {
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(taskWithStatus(HousekeepingTaskStatus.TODO)));

        assertThatThrownBy(() -> service.completeTask(1L))
                .isInstanceOf(HousekeepingConflictException.class)
                .hasMessageContaining("Only IN_PROGRESS housekeeping tasks can be completed");

        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
        verify(roomClient, never()).markRoomAvailable(any());
    }

    @Test
    void cancelTaskMovesTodoToCancelled() {
        HousekeepingTask task = taskWithStatus(HousekeepingTaskStatus.TODO);
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(task));
        mockSave();

        var response = service.cancelTask(1L, new CancelHousekeepingTaskRequest("Chambre bloquée"));

        assertThat(response.status()).isEqualTo(HousekeepingTaskStatus.CANCELLED);
        assertThat(response.cancelledAt()).isNotNull();
        assertThat(response.cancellationReason()).isEqualTo("Chambre bloquée");
        verify(roomClient, never()).markRoomAvailable(any());
    }

    @Test
    void cancelTaskMovesInProgressToCancelled() {
        HousekeepingTask task = taskWithStatus(HousekeepingTaskStatus.IN_PROGRESS);
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(task));
        mockSave();

        var response = service.cancelTask(1L, new CancelHousekeepingTaskRequest("Priorité modifiée"));

        assertThat(response.status()).isEqualTo(HousekeepingTaskStatus.CANCELLED);
        assertThat(response.cancelledAt()).isNotNull();
        assertThat(response.cancellationReason()).isEqualTo("Priorité modifiée");
        verify(roomClient).markRoomAvailable(301L);
    }

    @Test
    void updateTaskRejectsFinalTask() {
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(taskWithStatus(HousekeepingTaskStatus.DONE)));

        assertThatThrownBy(() -> service.updateTask(1L, new UpdateHousekeepingTaskRequest(
                HousekeepingTaskType.DEEP_CLEANING,
                Priority.URGENT,
                SCHEDULED_DATE,
                "Intervention prioritaire"
        ))).isInstanceOf(HousekeepingConflictException.class)
                .hasMessageContaining("Cannot modify a final housekeeping task");

        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
    }

    @Test
    void assignTaskRejectsFinalTask() {
        when(housekeepingTaskRepository.findById(1L)).thenReturn(Optional.of(taskWithStatus(HousekeepingTaskStatus.CANCELLED)));

        assertThatThrownBy(() -> service.assignTask(1L, new AssignHousekeepingTaskRequest(101L)))
                .isInstanceOf(HousekeepingConflictException.class)
                .hasMessageContaining("Only TODO or IN_PROGRESS housekeeping tasks can be assigned");

        verify(staffClient, never()).findSummaryById(any());
        verify(housekeepingTaskRepository, never()).save(any(HousekeepingTask.class));
    }

    private void mockSave() {
        when(housekeepingTaskRepository.save(any(HousekeepingTask.class))).thenAnswer(invocation -> {
            HousekeepingTask task = invocation.getArgument(0);
            if (task.getId() == null) {
                task.setId(1L);
            }
            if (task.getCreatedAt() == null) {
                task.setCreatedAt(LocalDateTime.now());
            }
            task.setUpdatedAt(LocalDateTime.now());
            return task;
        });
    }

    private HousekeepingTask taskWithStatus(HousekeepingTaskStatus status) {
        HousekeepingTask task = new HousekeepingTask();
        task.setId(1L);
        task.setRoomId(301L);
        task.setRoomNumber("301");
        task.setType(HousekeepingTaskType.STANDARD_CLEANING);
        task.setStatus(status);
        task.setPriority(Priority.MEDIUM);
        task.setScheduledDate(SCHEDULED_DATE);
        task.setCreatedAt(LocalDateTime.now().minusDays(1));
        task.setUpdatedAt(LocalDateTime.now().minusDays(1));
        return task;
    }

    private RoomSummaryResponse activeRoom() {
        return new RoomSummaryResponse(301L, "301", "CLEANING", true);
    }

    private StaffSummaryResponse activeAgent() {
        return new StaffSummaryResponse(101L, "Nadia El Amrani", "HOUSEKEEPING", true);
    }
}
