"use client";

import { AlertTriangle } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface CancelReservationDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    reservationId: number;
    isLoading?: boolean;
}

export function CancelReservationDialog({ isOpen, onClose, onConfirm, reservationId, isLoading }: CancelReservationDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Annuler la réservation"
            description="Cette action changera le statut en « Annulée »."
            icon={AlertTriangle}
            iconClassName="bg-red-100 text-red-600"
            confirmLabel="Confirmer l'annulation"
            cancelLabel="Fermer"
            danger
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Êtes-vous sûr de vouloir annuler la réservation{" "}
                <strong className="font-bold text-[var(--hms-text)]">#{reservationId}</strong> ?
            </p>
        </HmsActionModal>
    );
}
