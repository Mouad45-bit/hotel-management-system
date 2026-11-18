"use client";

import { RefreshCcw } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface ActivateRoomDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    roomNumber: string;
    isLoading?: boolean;
}

export function ActivateRoomDialog({ isOpen, onClose, onConfirm, roomNumber, isLoading }: ActivateRoomDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Réactiver la chambre"
            description="La chambre redeviendra disponible à la réservation."
            icon={RefreshCcw}
            iconClassName="bg-emerald-100 text-emerald-600"
            confirmLabel="Confirmer la réactivation"
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Êtes-vous sûr de vouloir réactiver la chambre{" "}
                <strong className="font-bold text-[var(--hms-text)]">{roomNumber}</strong> ?
                Elle sera de nouveau visible dans l&apos;inventaire principal et pourra être réservée.
            </p>
        </HmsActionModal>
    );
}
