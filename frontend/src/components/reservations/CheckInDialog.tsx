"use client";

import { LogIn } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface CheckInDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    reservationId: number;
    isLoading?: boolean;
}

export function CheckInDialog({ isOpen, onClose, onConfirm, reservationId, isLoading }: CheckInDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Confirmer le check-in"
            description="Le statut de la réservation passera à « Check-in »."
            icon={LogIn}
            iconClassName="bg-emerald-100 text-emerald-600"
            confirmLabel="Check-in"
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Confirmer l&apos;arrivée du client pour la réservation{" "}
                <strong className="font-bold text-[var(--hms-text)]">#{reservationId}</strong> ?
            </p>
        </HmsActionModal>
    );
}
