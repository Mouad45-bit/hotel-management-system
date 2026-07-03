"use client";

import Link from "next/link";
import { BedDouble, CalendarDays, FileText, Sparkles, UserRoundCog, Users } from "lucide-react";
import { HmsCard } from "@/components/hms/HmsCard";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { useAuth } from "@/contexts/AuthContext";

const modules = [
    { name: "Chambres", href: "/rooms", icon: BedDouble, description: "Inventaire et statut des chambres" },
    { name: "Clients", href: "/clients", icon: Users, description: "Fiches clients et historique" },
    { name: "Réservations", href: "/reservations", icon: CalendarDays, description: "Suivi des séjours" },
    { name: "Factures", href: "/invoices", icon: FileText, description: "Facturation et paiements" },
    { name: "Housekeeping", href: "/housekeeping", icon: Sparkles, description: "Tâches de ménage" },
    { name: "Personnel", href: "/staff", icon: UserRoundCog, description: "Gestion des employés" },
];

export default function HomePage() {
    const { user } = useAuth();

    return (
        <AppLayout>
            <PageHeader
                title={`Bonjour${user?.firstName ? `, ${user.firstName}` : ""}`}
                description="Bienvenue dans le back-office de Maison Lumière. Accédez rapidement à vos modules."
            />

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {modules.map(({ name, href, icon: Icon, description }) => (
                    <Link key={href} href={href}>
                        <HmsCard className="flex items-center gap-4 transition-shadow hover:shadow-md">
                            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white">
                                <Icon className="h-6 w-6" strokeWidth={1.8} />
                            </div>
                            <div>
                                <p className="font-semibold text-[var(--hms-text)]">{name}</p>
                                <p className="text-xs text-[var(--hms-text-muted)]">{description}</p>
                            </div>
                        </HmsCard>
                    </Link>
                ))}
            </div>
        </AppLayout>
    );
}
