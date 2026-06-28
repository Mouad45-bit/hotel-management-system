"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppLayout } from "@/components/layout/AppLayout";
import { PageHeader } from "@/components/layout/PageHeader";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsCard } from "@/components/hms/HmsCard";
import { ClientStatusBadge } from "@/components/clients/ClientStatusBadge";
import { DeactivateClientDialog } from "@/components/clients/DeactivateClientDialog";
import { ClientService } from "@/services/client.service";
import type { Client } from "@/types/client";
import {
    AlertCircle,
    CalendarDays,
    FileText,
    Mail,
    MapPin,
    Pencil,
    Phone,
    Power,
    RefreshCcw,
    Shield,
    User,
} from "lucide-react";

export default function ClientDetailPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [client, setClient] = useState<Client | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [confirmDeactivate, setConfirmDeactivate] = useState(false);
    const [isDeactivating, setIsDeactivating] = useState(false);

    const fetchClient = () => {
        setLoading(true);
        ClientService.getClientById(id)
            .then(setClient)
            .catch((err) => setError(err instanceof Error ? err.message : "Client introuvable"))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        fetchClient();
    }, [id]);

    const handleDeactivate = async () => {
        setIsDeactivating(true);
        try {
            await ClientService.deleteClient(id);
            router.push("/clients");
            router.refresh();
        } catch (err) {
            alert(err instanceof Error ? err.message : "Erreur lors de la désactivation");
            setConfirmDeactivate(false);
        } finally {
            setIsDeactivating(false);
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-[var(--hms-text-muted)]">
                    <RefreshCcw className="mr-2 h-4 w-4 animate-spin" strokeWidth={1.8} />
                    Chargement du client...
                </div>
            </AppLayout>
        );
    }

    if (error || !client) {
        return (
            <AppLayout>
                <HmsCard>
                    <div className="flex items-start gap-4">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-500" strokeWidth={1.8} />
                        <div>
                            <p className="font-semibold text-red-700">Client introuvable</p>
                            <p className="mt-1 text-sm text-red-600">{error}</p>
                        </div>
                    </div>
                </HmsCard>
            </AppLayout>
        );
    }

    const tiles = [
        { icon: Mail, label: "Email", value: client.email ?? "—" },
        { icon: Phone, label: "Téléphone", value: client.phone ?? "—" },
        { icon: Shield, label: "CIN", value: client.cin ?? "—" },
        { icon: User, label: "Passeport", value: client.passportNumber ?? "—" },
    ];

    return (
        <AppLayout>
            <PageHeader
                backHref="/clients"
                eyebrow={`CLIENT-${client.id}`}
                title={`${client.firstName} ${client.lastName}`}
                description="Fiche client : informations personnelles, moyens d'identification et accès aux actions principales."
                actions={
                    <>
                        <Link href={`/clients/${id}/edit`}>
                            <HmsButton>
                                <Pencil className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                                Modifier
                            </HmsButton>
                        </Link>
                        <HmsButton variant="danger" onClick={() => setConfirmDeactivate(true)}>
                            <Power className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Désactiver
                        </HmsButton>
                    </>
                }
            />

            <HmsCard>
                <div className="flex items-center justify-between">
                    <ClientStatusBadge active={client.active} />
                    {client.nationality && (
                        <span className="inline-flex items-center rounded-full bg-slate-50 px-3 py-1 text-xs font-medium text-[var(--hms-text)] ring-1 ring-inset ring-[var(--hms-soft-border)]">
                            {client.nationality}
                        </span>
                    )}
                </div>

                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                    {tiles.map(({ icon: Icon, label, value }) => (
                        <div key={label} className="rounded-2xl bg-slate-50 p-5 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-white text-[var(--hms-text-muted)] shadow-sm">
                                <Icon className="h-[18px] w-[18px]" strokeWidth={1.8} />
                            </div>
                            <p className="mt-4 text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">{label}</p>
                            <p className="mt-1 break-all text-sm font-bold text-[var(--hms-text)]">{value}</p>
                        </div>
                    ))}
                </div>

                {(client.address || client.birthDate) && (
                    <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
                        {client.birthDate && (
                            <div className="flex items-center gap-3 rounded-xl bg-slate-50 p-4 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                                <CalendarDays className="h-[18px] w-[18px] text-[var(--hms-text-muted)]" strokeWidth={1.8} />
                                <div>
                                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Date de naissance</p>
                                    <p className="mt-0.5 text-sm font-medium text-[var(--hms-text)]">{client.birthDate}</p>
                                </div>
                            </div>
                        )}
                        {client.address && (
                            <div className="flex items-center gap-3 rounded-xl bg-slate-50 p-4 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                                <MapPin className="h-[18px] w-[18px] text-[var(--hms-text-muted)]" strokeWidth={1.8} />
                                <div>
                                    <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Adresse</p>
                                    <p className="mt-0.5 text-sm font-medium text-[var(--hms-text)]">{client.address}</p>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </HmsCard>

            <HmsCard className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                <div>
                    <p className="text-sm font-medium text-[var(--hms-text-muted)]">Client enregistré le</p>
                    <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">
                        {client.createdAt ? new Date(client.createdAt).toLocaleDateString("fr-FR") : "—"}
                    </p>
                </div>
                <div className="flex flex-wrap gap-3">
                    <Link href={`/clients/${id}/invoices`}>
                        <HmsButton variant="secondary">
                            <FileText className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Factures
                        </HmsButton>
                    </Link>
                    <Link href={`/reservations?clientId=${id}`}>
                        <HmsButton>
                            <CalendarDays className="h-4 w-4" strokeWidth={1.8} aria-hidden="true" />
                            Réservations
                        </HmsButton>
                    </Link>
                </div>
            </HmsCard>

            <DeactivateClientDialog
                isOpen={confirmDeactivate}
                onClose={() => setConfirmDeactivate(false)}
                onConfirm={handleDeactivate}
                clientName={`${client.firstName} ${client.lastName}`}
                isLoading={isDeactivating}
            />
        </AppLayout>
    );
}
