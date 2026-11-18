"use client";

import { LogOut } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface CheckOutDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    reservationId: number;
    isLoading?: boolean;
}

export function CheckOutDialog({ isOpen, onClose, onConfirm, reservationId, isLoading }: CheckOutDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Confirmer le check-out"
            description="Le statut de la réservation passera à « Check-out »."
            icon={LogOut}
            iconClassName="bg-indigo-100 text-indigo-600"
            confirmLabel="Check-out"
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Confirmer le départ du client pour la réservation{" "}
                <strong className="font-bold text-[var(--hms-text)]">#{reservationId}</strong> ?
            </p>
        </HmsActionModal>
    );
}
