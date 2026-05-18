import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { AppLayout } from "@/components/layout/AppLayout";

export default function RoomsPage() {
    return (
        <AppLayout
            title="Chambres"
            description="Gestion de l’inventaire des chambres de l’hôtel"
        >
            <div className="space-y-6">
                <HmsCard>
                    <div className="flex items-center justify-between gap-4">
                        <div>
                            <p className="text-sm font-medium text-stone-700">
                                Module Room
                            </p>

                            <h2 className="mt-2 text-xl font-semibold tracking-tight text-zinc-950">
                                Préparation de l’interface Chambres
                            </h2>

                            <p className="mt-2 max-w-2xl text-sm leading-6 text-zinc-500">
                                Cette page servira à afficher la liste, les filtres, les
                                statistiques et les actions du module Room.
                            </p>
                        </div>

                        <HmsButton>Ajouter une chambre</HmsButton>
                    </div>
                </HmsCard>

                <div className="grid gap-4 md:grid-cols-4">
                    <HmsCard>
                        <p className="text-sm text-zinc-500">Total chambres</p>
                        <p className="mt-2 text-2xl font-semibold text-zinc-950">—</p>
                    </HmsCard>

                    <HmsCard>
                        <p className="text-sm text-zinc-500">Disponibles</p>
                        <p className="mt-2 text-2xl font-semibold text-emerald-700">—</p>
                    </HmsCard>

                    <HmsCard>
                        <p className="text-sm text-zinc-500">Occupées</p>
                        <p className="mt-2 text-2xl font-semibold text-orange-700">—</p>
                    </HmsCard>

                    <HmsCard>
                        <p className="text-sm text-zinc-500">Maintenance</p>
                        <p className="mt-2 text-2xl font-semibold text-zinc-700">—</p>
                    </HmsCard>
                </div>

                <HmsCard>
                    <p className="text-sm font-medium text-zinc-950">
                        Tableau des chambres
                    </p>

                    <p className="mt-2 text-sm text-zinc-500">
                        Le tableau réel sera développé dans le Sprint 5 avec Tailwind CSS,
                        Headless UI pour les interactions et Heroicons pour les icônes.
                    </p>
                </HmsCard>
            </div>
        </AppLayout>
    );
}
