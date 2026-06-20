'use client';

import { AlertTriangle, X } from 'lucide-react';

interface DeactivateClientDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    clientName: string;
    isLoading?: boolean;
}

export function DeactivateClientDialog({ isOpen, onClose, onConfirm, clientName, isLoading }: DeactivateClientDialogProps) {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center px-4">
            <div
                className="absolute inset-0 bg-zinc-900/30 backdrop-blur-sm transition-opacity"
                onClick={isLoading ? undefined : onClose}
            />
            <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md p-6 animate-in fade-in zoom-in-95 duration-200">
                <button
                    onClick={onClose}
                    disabled={isLoading}
                    className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-600 transition"
                >
                    <X size={20} />
                </button>

                <div className="flex items-center gap-4 mb-4">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-orange-100">
                        <AlertTriangle className="h-5 w-5 text-orange-600" />
                    </div>
                    <h3 className="text-lg font-semibold leading-6 text-zinc-900">Désactiver le client</h3>
                </div>

                <p className="text-sm text-zinc-500 mb-6">
                    Êtes-vous sûr de vouloir désactiver le client <strong className="text-zinc-900 font-bold">{clientName}</strong> ?
                    Il n&apos;apparaîtra plus dans la liste active et ne pourra plus être utilisé pour une nouvelle réservation.
                </p>

                <div className="flex justify-end gap-3">
                    <button
                        type="button"
                        onClick={onClose}
                        disabled={isLoading}
                        className="px-4 py-2 text-sm font-semibold text-zinc-700 bg-white border border-zinc-200 rounded-xl hover:bg-zinc-50 transition"
                    >
                        Annuler
                    </button>
                    <button
                        type="button"
                        onClick={onConfirm}
                        disabled={isLoading}
                        className="px-4 py-2 text-sm font-semibold text-white bg-orange-500 rounded-xl hover:bg-orange-600 transition disabled:opacity-50"
                    >
                        {isLoading ? 'Désactivation...' : 'Confirmer'}
                    </button>
                </div>
            </div>
        </div>
    );
}
