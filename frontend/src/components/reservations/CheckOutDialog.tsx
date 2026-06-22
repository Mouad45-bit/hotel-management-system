'use client';

import { LogOut, X } from 'lucide-react';

interface CheckOutDialogProps {
    isOpen: boolean;
    onClose: () => void;
    onConfirm: () => void;
    reservationId: number;
    isLoading?: boolean;
}

export function CheckOutDialog({ isOpen, onClose, onConfirm, reservationId, isLoading }: CheckOutDialogProps) {
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
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-indigo-100">
                        <LogOut className="h-5 w-5 text-indigo-600" />
                    </div>
                    <h3 className="text-lg font-semibold leading-6 text-zinc-900">Confirmer le check-out</h3>
                </div>

                <p className="text-sm text-zinc-500 mb-6">
                    Confirmer le départ du client pour la réservation <strong className="text-zinc-900 font-bold">#{reservationId}</strong> ?
                    Le statut passera à &quot;Check-out&quot;.
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
                        className="px-4 py-2 text-sm font-semibold text-white bg-indigo-500 rounded-xl hover:bg-indigo-600 transition disabled:opacity-50"
                    >
                        {isLoading ? 'En cours...' : 'Check-out'}
                    </button>
                </div>
            </div>
        </div>
    );
}
