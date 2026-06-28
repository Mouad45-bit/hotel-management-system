"use client";

import { RefreshCcw } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface ActivateClientDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    clientName: string;
    isLoading?: boolean;
}

export function ActivateClientDialog({ isOpen, onClose, onConfirm, clientName, isLoading }: ActivateClientDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Réactiver le client"
            description="Le client redeviendra disponible pour les réservations."
            icon={RefreshCcw}
            iconClassName="bg-emerald-100 text-emerald-600"
            confirmLabel="Confirmer"
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Réactiver le client{" "}
                <strong className="font-bold text-[var(--hms-text)]">{clientName}</strong> ?
                Il redeviendra disponible pour les nouvelles réservations.
            </p>
        </HmsActionModal>
    );
}
