import type {
    HousekeepingAgentOption,
    HousekeepingRoomOption,
    HousekeepingTask,
    RoomCleaningHistoryItem,
} from "@/types/housekeeping";

export const mockHousekeepingAgents: HousekeepingAgentOption[] = [
    {
        id: 101,
        fullName: "Nadia El Amrani",
        role: "HOUSEKEEPING_AGENT",
        active: true,
    },
    {
        id: 102,
        fullName: "Youssef Bennani",
        role: "HOUSEKEEPING_AGENT",
        active: true,
    },
    {
        id: 103,
        fullName: "Salma Idrissi",
        role: "HOUSEKEEPING_SUPERVISOR",
        active: true,
    },
    {
        id: 104,
        fullName: "Karim Alaoui",
        role: "HOUSEKEEPING_AGENT",
        active: false,
    },
];

export const mockHousekeepingRooms: HousekeepingRoomOption[] = [
    { id: 201, roomNumber: "201", floor: 2, status: "DIRTY" },
    { id: 202, roomNumber: "202", floor: 2, status: "CLEANING" },
    { id: 203, roomNumber: "203", floor: 2, status: "AVAILABLE" },
    { id: 301, roomNumber: "301", floor: 3, status: "DIRTY" },
    { id: 302, roomNumber: "302", floor: 3, status: "MAINTENANCE" },
    { id: 401, roomNumber: "401", floor: 4, status: "OCCUPIED" },
];

export const mockHousekeepingTasks: HousekeepingTask[] = [
    {
        id: 1,
        roomId: 201,
        roomNumber: "201",
        reservationId: 9001,
        assignedAgentId: 101,
        assignedAgentName: "Nadia El Amrani",
        type: "STANDARD_CLEANING",
        status: "TODO",
        priority: "HIGH",
        scheduledDate: "2026-06-19",
        notes: "Nettoyage automatique simulé après check-out.",
        createdAt: "2026-06-19T08:15:00",
        updatedAt: "2026-06-19T08:15:00",
    },
    {
        id: 2,
        roomId: 202,
        roomNumber: "202",
        reservationId: 9002,
        assignedAgentId: 102,
        assignedAgentName: "Youssef Bennani",
        type: "DEEP_CLEANING",
        status: "IN_PROGRESS",
        priority: "URGENT",
        scheduledDate: "2026-06-19",
        startedAt: "2026-06-19T09:05:00",
        notes: "Chambre prioritaire à remettre en vente avant 13h.",
        createdAt: "2026-06-19T08:30:00",
        updatedAt: "2026-06-19T09:05:00",
    },
    {
        id: 3,
        roomId: 203,
        roomNumber: "203",
        assignedAgentId: 101,
        assignedAgentName: "Nadia El Amrani",
        type: "INSPECTION",
        status: "DONE",
        priority: "MEDIUM",
        scheduledDate: "2026-06-19",
        startedAt: "2026-06-19T07:45:00",
        completedAt: "2026-06-19T08:10:00",
        notes: "Contrôle qualité terminé, chambre disponible.",
        createdAt: "2026-06-19T07:20:00",
        updatedAt: "2026-06-19T08:10:00",
    },
    {
        id: 4,
        roomId: 301,
        roomNumber: "301",
        reservationId: 9004,
        type: "STANDARD_CLEANING",
        status: "TODO",
        priority: "URGENT",
        scheduledDate: "2026-06-19",
        notes: "Non assignée, client attendu en fin d'après-midi.",
        createdAt: "2026-06-19T10:00:00",
        updatedAt: "2026-06-19T10:00:00",
    },
    {
        id: 5,
        roomId: 302,
        roomNumber: "302",
        assignedAgentId: 103,
        assignedAgentName: "Salma Idrissi",
        type: "LIGHT_MAINTENANCE",
        status: "CANCELLED",
        priority: "LOW",
        scheduledDate: "2026-06-19",
        cancelledAt: "2026-06-19T11:15:00",
        cancellationReason: "Intervention maintenance reportée.",
        createdAt: "2026-06-19T09:40:00",
        updatedAt: "2026-06-19T11:15:00",
    },
    {
        id: 6,
        roomId: 401,
        roomNumber: "401",
        assignedAgentId: 102,
        assignedAgentName: "Youssef Bennani",
        type: "STANDARD_CLEANING",
        status: "TODO",
        priority: "MEDIUM",
        scheduledDate: "2026-06-20",
        notes: "Nettoyage planifié après départ tardif.",
        createdAt: "2026-06-18T17:20:00",
        updatedAt: "2026-06-18T17:20:00",
    },
    {
        id: 7,
        roomId: 201,
        roomNumber: "201",
        assignedAgentId: 101,
        assignedAgentName: "Nadia El Amrani",
        type: "DEEP_CLEANING",
        status: "DONE",
        priority: "HIGH",
        scheduledDate: "2026-06-17",
        startedAt: "2026-06-17T10:00:00",
        completedAt: "2026-06-17T11:25:00",
        notes: "Nettoyage approfondi mensuel.",
        createdAt: "2026-06-17T08:00:00",
        updatedAt: "2026-06-17T11:25:00",
    },
];

export const mockRoomCleaningHistory: RoomCleaningHistoryItem[] =
    mockHousekeepingTasks.map((task) => ({
        ...task,
        durationMinutes:
            task.startedAt && task.completedAt
                ? Math.round(
                      (new Date(task.completedAt).getTime() -
                          new Date(task.startedAt).getTime()) /
                          60000
                  )
                : null,
    }));
