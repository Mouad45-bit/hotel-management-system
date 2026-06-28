"use client";

import { useState, useEffect } from "react";
import { Repeat } from "lucide-react";
import type { RoomStatus } from "@/types/room";
import { HmsActionModal } from "@/components/hms/HmsActionModal";
import { HmsSelect } from "@/components/hms/HmsField";
import { RoomStatusBadge } from "./RoomStatusBadge";

interface ChangeRoomStatusDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: (newStatus: RoomStatus) => Promise<void>;
    currentStatus: RoomStatus;
    roomNumber: string;
}

const STATUS_OPTIONS: Record<RoomStatus, string> = {
    AVAILABLE: "Disponible",
    RESERVED: "Réservée",
    OCCUPIED: "Occupée",
    CLEANING: "Nettoyage",
    MAINTENANCE: "Maintenance",
    OUT_OF_SERVICE: "Hors service",
};

export function ChangeRoomStatusDialog({ isOpen, onClose, onConfirm, currentStatus, roomNumber }: ChangeRoomStatusDialogProps) {
    const [selectedStatus, setSelectedStatus] = useState<RoomStatus>(currentStatus);
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        if (isOpen) setSelectedStatus(currentStatus);
    }, [isOpen, currentStatus]);

    const handleSubmit = async () => {
        setIsLoading(true);
        try {
            await onConfirm(selectedStatus);
            onClose();
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <HmsActionModal
            open={isOpen}
            title="Modifier le statut"
            description={`Mettez à jour l'état opérationnel de la chambre ${roomNumber}.`}
            icon={Repeat}
            iconClassName="bg-blue-50 text-blue-600"
            confirmLabel="Appliquer le statut"
            submitting={isLoading}
            confirmDisabled={selectedStatus === currentStatus}
            onClose={onClose}
            onConfirm={handleSubmit}
        >
            <div className="space-y-4">
                <div className="flex items-center justify-between rounded-xl bg-slate-50 p-3 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                    <span className="text-sm font-medium text-[var(--hms-text-muted)]">Statut actuel</span>
                    <RoomStatusBadge status={currentStatus} />
                </div>

                <HmsSelect
                    id="room-status-select"
                    label="Nouveau statut"
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value as RoomStatus)}
                >
                    {(Object.keys(STATUS_OPTIONS) as RoomStatus[]).map((s) => (
                        <option key={s} value={s}>{STATUS_OPTIONS[s]}</option>
                    ))}
                </HmsSelect>
            </div>
        </HmsActionModal>
    );
}
