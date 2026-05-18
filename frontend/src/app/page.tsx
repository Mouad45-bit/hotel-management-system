import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { AppLayout } from "@/components/layout/AppLayout";

export default function HomePage() {
    return (
        <AppLayout
            title="Dashboard"
            description="Vue générale du système de gestion hôtelière"
        >
            <HmsCard>
                <p className="text-sm font-medium text-stone-700">Bienvenue dans HMS</p>

                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-zinc-950">
                    Système de gestion d’hôtel
                </h2>

                <p className="mt-3 max-w-2xl text-sm leading-6 text-zinc-500">
                    Le premier module démontrable sera la gestion des chambres. Cette
                    interface servira de base visuelle pour les prochains modules.
                </p>

                <div className="mt-6">
                    <a href="/rooms">
                        <HmsButton>Ouvrir le module Chambres</HmsButton>
                    </a>
                </div>
            </HmsCard>
        </AppLayout>
    );
}
