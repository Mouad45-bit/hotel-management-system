'use client';

import { useState, useEffect } from 'react';
import { RoomStatus } from '@/types/room';
import { Repeat, X } from 'lucide-react';
import { RoomStatusBadge } from './RoomStatusBadge';

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

    // Réinitialise le select si on rouvre la modale
    useEffect(() => {
        if (isOpen) setSelectedStatus(currentStatus);
    }, [isOpen, currentStatus]);

    if (!isOpen) return null;

    const handleSubmit = async () => {
        setIsLoading(true);
        try {
            await onConfirm(selectedStatus);
            onClose();
        } catch (error) {
            alert("Erreur lors du changement de statut");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
            <div className="absolute inset-0 bg-zinc-900/30 backdrop-blur-sm transition-opacity" onClick={isLoading ? undefined : onClose} />

            <div className="relative w-full max-w-sm animate-in fade-in zoom-in-95 rounded-2xl bg-white p-6 shadow-xl duration-200">
                <button onClick={onClose} disabled={isLoading} className="absolute right-4 top-4 text-zinc-400 transition hover:text-zinc-600">
                    <X size={20} />
                </button>

                <div className="mb-4 flex items-center gap-4">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-blue-50">
                        <Repeat className="h-5 w-5 text-blue-600" />
                    </div>
                    <h3 className="text-lg font-semibold leading-6 text-zinc-900">
                        Modifier le statut
                    </h3>
                </div>

                <p className="mb-4 text-sm text-zinc-500">
                    Mettez à jour l'état opérationnel de la chambre <strong className="text-zinc-900">{roomNumber}</strong>.
                </p>

                <div className="mb-6 space-y-3">
                    <div className="flex items-center justify-between rounded-xl bg-zinc-50 p-3 ring-1 ring-inset ring-zinc-200">
                        <span className="text-sm font-medium text-zinc-600">Statut actuel</span>
                        <RoomStatusBadge status={currentStatus} />
                    </div>

                    <div>
                        <label className="mb-1.5 block text-sm font-semibold text-zinc-900">Nouveau statut</label>
                        <select
                            value={selectedStatus}
                            onChange={(e) => setSelectedStatus(e.target.value as RoomStatus)}
                            className="w-full rounded-xl border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition focus:border-zinc-900 focus:ring-1 focus:ring-zinc-900"
                        >
                            {(Object.keys(STATUS_OPTIONS) as RoomStatus[]).map((s) => (
                                <option key={s} value={s}>{STATUS_OPTIONS[s]}</option>
                            ))}
                        </select>
                    </div>
                </div>

                <div className="flex justify-end gap-3">
                    <button
                        type="button"
                        className="rounded-xl border border-zinc-200 bg-white px-4 py-2 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-50"
                        onClick={onClose}
                        disabled={isLoading}
                    >
                        Annuler
                    </button>
                    <button
                        type="button"
                        className="rounded-xl bg-zinc-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-zinc-800 disabled:opacity-50"
                        onClick={handleSubmit}
                        disabled={isLoading || selectedStatus === currentStatus}
                    >
                        {isLoading ? 'Mise à jour...' : 'Appliquer le statut'}
                    </button>
                </div>
            </div>
        </div>
    );
}
