"use client";

import { AlertTriangle } from "lucide-react";
import { HmsActionModal } from "@/components/hms/HmsActionModal";

interface DeactivateClientDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    clientName: string;
    isLoading?: boolean;
}

export function DeactivateClientDialog({ isOpen, onClose, onConfirm, clientName, isLoading }: DeactivateClientDialogProps) {
    return (
        <HmsActionModal
            open={isOpen}
            title="Désactiver le client"
            description="Cette action est réversible. Le client pourra être réactivé ultérieurement."
            icon={AlertTriangle}
            iconClassName="bg-orange-100 text-orange-600"
            confirmLabel="Confirmer"
            danger
            submitting={isLoading}
            onClose={onClose}
            onConfirm={onConfirm}
        >
            <p className="text-sm text-[var(--hms-text-muted)]">
                Êtes-vous sûr de vouloir désactiver le client{" "}
                <strong className="font-bold text-[var(--hms-text)]">{clientName}</strong> ?
                Il n&apos;apparaîtra plus dans la liste active et ne pourra plus être utilisé
                pour une nouvelle réservation.
            </p>
        </HmsActionModal>
    );
}
