"use client";

export default function ErrorPage() {
    return (
        <div className="flex min-h-screen items-center justify-center bg-zinc-50">
            <div className="rounded-2xl border border-red-200 bg-white p-6 shadow-sm">
                <h2 className="text-lg font-semibold text-red-700">
                    Une erreur est survenue
                </h2>

                <p className="mt-2 text-sm text-zinc-500">
                    Veuillez réessayer ou vérifier le serveur.
                </p>
            </div>
        </div>
    );
}
