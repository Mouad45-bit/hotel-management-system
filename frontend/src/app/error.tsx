"use client";

import { HmsButton } from "@/components/hms/HmsButton";

export default function ErrorPage({
    error,
    reset,
}: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return (
        <div className="flex min-h-screen items-center justify-center bg-[var(--hms-page)]">
            <div className="w-full max-w-sm rounded-[20px] border border-[var(--hms-soft-border)] bg-[var(--hms-surface)] p-6 shadow-[0_16px_40px_rgba(13,9,7,0.03)]">
                <h2 className="text-lg font-bold text-red-700">
                    Une erreur est survenue
                </h2>
                <p className="mt-2 text-sm text-[var(--hms-text-muted)]">
                    {error.message || "Veuillez réessayer ou vérifier le serveur."}
                </p>
                <HmsButton onClick={reset} className="mt-4">
                    Réessayer
                </HmsButton>
            </div>
        </div>
    );
}
