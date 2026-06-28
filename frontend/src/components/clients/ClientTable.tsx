import Link from "next/link";
import { Eye, Pencil, Power, RefreshCcw, Users } from "lucide-react";
import type { Client } from "@/types/client";
import { ClientStatusBadge } from "./ClientStatusBadge";

interface ClientTableProps {
    clients: Client[];
    onDeactivateClick: (client: Client) => void;
    onActivateClick?: (client: Client) => void;
}

export function ClientTable({ clients, onDeactivateClick, onActivateClick }: ClientTableProps) {
    if (clients.length === 0) {
        return (
            <div className="flex min-h-60 items-center justify-center px-6 py-12">
                <div className="text-center">
                    <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-[var(--hms-text-muted)]">
                        <Users className="h-6 w-6" strokeWidth={1.8} />
                    </div>
                    <p className="mt-4 text-sm font-semibold text-[var(--hms-text)]">Aucun client trouvé</p>
                    <p className="mt-2 text-sm text-[var(--hms-text-muted)]">Aucun client ne correspond aux critères de recherche.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full table-auto border-collapse">
                <thead className="bg-slate-50">
                    <tr>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Nom</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Email</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Téléphone</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">CIN</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Nationalité</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-left text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Statut</th>
                        <th className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 text-right text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Actions</th>
                    </tr>
                </thead>
                <tbody className="bg-white">
                    {clients.map((client) => (
                        <tr key={client.id} className="transition-colors hover:bg-slate-50">
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm font-bold text-[var(--hms-text)]">
                                    {client.firstName} {client.lastName}
                                </p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text-muted)]">
                                    {client.email ?? "—"}
                                </p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text-muted)]">
                                    {client.phone ?? "—"}
                                </p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                {client.cin ? (
                                    <span className="inline-flex items-center rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-bold text-[var(--hms-text)]">
                                        {client.cin}
                                    </span>
                                ) : (
                                    <span className="text-sm text-[var(--hms-text-muted)]">—</span>
                                )}
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <p className="text-sm text-[var(--hms-text-muted)]">
                                    {client.nationality ?? "—"}
                                </p>
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <ClientStatusBadge active={client.active} />
                            </td>
                            <td className="whitespace-nowrap border-b border-[var(--hms-soft-border)] px-3 py-3 align-top">
                                <div className="flex justify-end gap-1.5">
                                    <Link
                                        href={`/clients/${client.id}`}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        title="Voir le détail"
                                    >
                                        <Eye className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    <Link
                                        href={`/clients/${client.id}/edit`}
                                        className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--hms-border)] bg-white text-[var(--hms-text-muted)] transition-colors hover:bg-slate-50 hover:text-[var(--hms-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                        title="Modifier"
                                    >
                                        <Pencil className="h-4 w-4" strokeWidth={1.8} />
                                    </Link>
                                    {client.active ? (
                                        <button
                                            onClick={() => onDeactivateClick(client)}
                                            className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-orange-200 bg-white text-orange-600 transition-colors hover:bg-orange-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            title="Désactiver le client"
                                        >
                                            <Power className="h-4 w-4" strokeWidth={1.8} />
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => onActivateClick?.(client)}
                                            className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-200 bg-white text-emerald-700 transition-colors hover:bg-emerald-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--hms-focus)] focus-visible:ring-offset-2"
                                            title="Réactiver le client"
                                        >
                                            <RefreshCcw className="h-4 w-4" strokeWidth={1.8} />
                                        </button>
                                    )}
                                </div>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}
