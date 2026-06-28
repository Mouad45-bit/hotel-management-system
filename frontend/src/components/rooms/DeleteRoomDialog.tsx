"use client";

import { AlertTriangle } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface DeleteRoomDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    roomNumber: string;
    isLoading?: boolean;
}

export function DeleteRoomDialog({ isOpen, onClose, onConfirm, roomNumber, isLoading }: DeleteRoomDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Désactiver la chambre"
            description="Suppression logique — la chambre pourra être réactivée."
            icon={AlertTriangle}
            iconClassName="bg-red-100 text-red-600"
            confirmLabel="Confirmer"
            danger
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Êtes-vous sûr de vouloir désactiver la chambre{" "}
                <strong className="font-bold text-[var(--hms-text)]">{roomNumber}</strong> ?
                Elle n&apos;apparaîtra plus dans la liste active et ne pourra plus être réservée.
            </p>
        </HmsActionModal>
    );
}
