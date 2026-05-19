"use client";

import { useState } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { RoomStatsCards } from "@/components/rooms/RoomStatsCards";
import { RoomFilters } from "@/components/rooms/RoomFilters";
import { RoomTable } from "@/components/rooms/RoomTable";
import { RoomForm } from "@/components/rooms/RoomForm";
import { DeleteRoomDialog } from "@/components/rooms/DeleteRoomDialog";
import { RoomDetailsPanel } from "@/components/rooms/RoomDetailsPanel";
import { mockRooms } from "@/data/mockRooms";
import {
    Room,
    RoomFiltersState,
    DEFAULT_ROOM_FILTERS,
} from "@/types/room";
import { RoomFormValues } from "@/schemas/room.schema";

// ─── Types pour les modes d'affichage ────────────────────────────────────────
type ViewMode = "list" | "create" | "edit";

export default function RoomsPage() {
    // ─── État principal : liste des chambres ─────────────────────────────────
    const [rooms, setRooms] = useState<Room[]>(mockRooms);

    // ─── État des filtres ────────────────────────────────────────────────────
    const [filters, setFilters] = useState<RoomFiltersState>(DEFAULT_ROOM_FILTERS);

    // ─── État de navigation / mode ───────────────────────────────────────────
    const [viewMode, setViewMode] = useState<ViewMode>("list");
    const [selectedRoom, setSelectedRoom] = useState<Room | null>(null);

    // ─── État des dialogs ────────────────────────────────────────────────────
    const [roomToDelete, setRoomToDelete] = useState<Room | null>(null);
    const [roomToView, setRoomToView] = useState<Room | null>(null);

    // ─── Filtrage local ──────────────────────────────────────────────────────
    const filteredRooms = rooms.filter(room => {
        if (!room.active) return false;

        if (filters.number && !room.number.toLowerCase().includes(filters.number.toLowerCase())) {
            return false;
        }
        if (filters.type && room.type !== filters.type) {
            return false;
        }
        if (filters.status && room.status !== filters.status) {
            return false;
        }
        if (filters.floor && room.floor !== Number(filters.floor)) {
            return false;
        }
        if (filters.capacity && room.capacity !== Number(filters.capacity)) {
            return false;
        }
        return true;
    });

    // ─── Actions locales ─────────────────────────────────────────────────────
    const handleCreate = (data: RoomFormValues) => {
        const now = new Date().toISOString();
        const newRoom: Room = {
            ...data,
            id: Math.max(0, ...rooms.map(r => r.id)) + 1,
            active: true,
            createdAt: now,
            updatedAt: now,
        };
        setRooms(prev => [...prev, newRoom]);
        setViewMode("list");
    };

    const handleEdit = (data: RoomFormValues) => {
        if (!selectedRoom) return;
        setRooms(prev =>
            prev.map(r =>
                r.id === selectedRoom.id
                    ? { ...r, ...data, updatedAt: new Date().toISOString() }
                    : r
            )
        );
        setSelectedRoom(null);
        setViewMode("list");
    };

    const handleDelete = () => {
        if (!roomToDelete) return;
        setRooms(prev =>
            prev.map(r =>
                r.id === roomToDelete.id ? { ...r, active: false } : r
            )
        );
        setRoomToDelete(null);
    };

    const handleStatusChange = (room: Room, newStatus: Room["status"]) => {
        setRooms(prev =>
            prev.map(r =>
                r.id === room.id
                    ? { ...r, status: newStatus, updatedAt: new Date().toISOString() }
                    : r
            )
        );
    };

    // ─── Rendu : Formulaire de création ──────────────────────────────────────
    if (viewMode === "create") {
        return (
            <AppLayout title="Chambres" description="Ajouter une nouvelle chambre">
                <RoomForm
                    onSubmit={handleCreate}
                    onCancel={() => setViewMode("list")}
                />
            </AppLayout>
        );
    }

    // ─── Rendu : Formulaire de modification ──────────────────────────────────
    if (viewMode === "edit" && selectedRoom) {
        return (
            <AppLayout title="Chambres" description={`Modifier la chambre ${selectedRoom.number}`}>
                <RoomForm
                    initialData={{
                        number: selectedRoom.number,
                        floor: selectedRoom.floor,
                        type: selectedRoom.type,
                        pricePerNight: selectedRoom.pricePerNight,
                        capacity: selectedRoom.capacity,
                        status: selectedRoom.status,
                        description: selectedRoom.description,
                    }}
                    onSubmit={handleEdit}
                    onCancel={() => {
                        setSelectedRoom(null);
                        setViewMode("list");
                    }}
                />
            </AppLayout>
        );
    }

    // ─── Rendu principal : liste ─────────────────────────────────────────────
    return (
        <AppLayout title="Chambres" description="Gestion de l'inventaire des chambres de l'hôtel">
            <div className="space-y-6">
                {/* En-tête avec bouton d'ajout */}
                <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-zinc-950">
                        Inventaire des chambres
                    </h2>
                    <HmsButton onClick={() => setViewMode("create")}>
                        Ajouter une chambre
                    </HmsButton>
                </div>

                {/* Statistiques */}
                <RoomStatsCards rooms={filteredRooms} />

                {/* Filtres */}
                <RoomFilters filters={filters} onChange={setFilters} />

                {/* Tableau */}
                <HmsCard>
                    <RoomTable
                        rooms={filteredRooms}
                        onView={room => setRoomToView(room)}
                        onEdit={room => {
                            setSelectedRoom(room);
                            setViewMode("edit");
                        }}
                        onDelete={room => setRoomToDelete(room)}
                        onStatusChange={handleStatusChange}
                    />
                </HmsCard>
            </div>

            {/* Dialog de suppression */}
            <DeleteRoomDialog
                isOpen={!!roomToDelete}
                roomNumber={roomToDelete?.number ?? ""}
                onClose={() => setRoomToDelete(null)}
                onConfirm={handleDelete}
            />

            {/* Panneau de détail */}
            {roomToView && (
                <RoomDetailsPanel
                    room={roomToView}
                    onClose={() => setRoomToView(null)}
                />
            )}
        </AppLayout>
    );
}
