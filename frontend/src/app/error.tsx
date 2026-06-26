"use client";

export default function ErrorPage({
    error,
    reset,
}: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return (
        <div className="flex min-h-screen items-center justify-center bg-zinc-50">
            <div className="rounded-2xl border border-red-200 bg-white p-6 shadow-sm max-w-sm w-full">
                <h2 className="text-lg font-semibold text-red-700">
                    Une erreur est survenue
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                    {error.message || "Veuillez réessayer ou vérifier le serveur."}
                </p>

                <button
                    onClick={reset}
                    className="mt-4 rounded-xl bg-zinc-900 px-4 py-2 text-sm font-semibold text-white hover:bg-zinc-800 transition"
                >
                    Réessayer
                </button>
            </div>
        </div>
    );
}
