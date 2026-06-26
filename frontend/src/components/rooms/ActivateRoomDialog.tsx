'use client';

import { RefreshCcw, X } from 'lucide-react';

interface ActivateRoomDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    roomNumber: string;
    isLoading?: boolean;
}

export function ActivateRoomDialog({ isOpen, onClose, onConfirm, roomNumber, isLoading }: ActivateRoomDialogProps) {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
            {/* Fond sombre cliquable pour fermer */}
            <div
                className="absolute inset-0 bg-zinc-900/30 backdrop-blur-sm transition-opacity"
                onClick={isLoading ? undefined : onClose}
            />

            {/* Contenu de la modale */}
            <div className="relative w-full max-w-md animate-in fade-in zoom-in-95 rounded-2xl bg-white p-6 shadow-xl duration-200">

                {/* Bouton croix en haut à droite */}
                <button
                    onClick={onClose}
                    disabled={isLoading}
                    className="absolute right-4 top-4 text-zinc-400 transition hover:text-zinc-600"
                >
                    <X size={20} />
                </button>

                <div className="mb-4 flex items-center gap-4">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-emerald-100">
                        <RefreshCcw className="h-5 w-5 text-emerald-600" />
                    </div>
                    <h3 className="text-lg font-semibold leading-6 text-zinc-900">
                        Réactiver la chambre
                    </h3>
                </div>

                <p className="mb-6 text-sm text-zinc-500">
                    Êtes-vous sûr de vouloir réactiver la chambre <strong className="font-bold text-zinc-900">{roomNumber}</strong> ?
                    Elle sera de nouveau visible dans l'inventaire principal et pourra être réservée par les clients.
                </p>

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
                        className="rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-emerald-700 disabled:opacity-50"
                        onClick={onConfirm}
                        disabled={isLoading}
                    >
                        {isLoading ? 'Réactivation...' : 'Confirmer la réactivation'}
                    </button>
                </div>
            </div>
        </div>
    );
}
