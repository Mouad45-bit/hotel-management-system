import Link from 'next/link';
import { Client } from '@/types/client';
import { Eye, Pencil, Power, RefreshCcw } from 'lucide-react';
import { ClientStatusBadge } from './ClientStatusBadge';

interface ClientTableProps {
    clients: Client[];
    onDeactivateClick: (client: Client) => void;
    onActivateClick?: (client: Client) => void;
}

export function ClientTable({ clients, onDeactivateClick, onActivateClick }: ClientTableProps) {
    return (
        <div className="overflow-hidden rounded-2xl bg-white shadow-sm ring-1 ring-zinc-200">
            <table className="w-full text-left text-sm">
                <thead className="border-b border-zinc-200 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                    <tr>
                        <th className="px-6 py-4">Nom</th>
                        <th className="px-6 py-4">Email</th>
                        <th className="px-6 py-4">Téléphone</th>
                        <th className="px-6 py-4">CIN</th>
                        <th className="px-6 py-4">Nationalité</th>
                        <th className="px-6 py-4">Statut</th>
                        <th className="px-6 py-4 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-zinc-100">
                    {clients.length === 0 ? (
                        <tr>
                            <td colSpan={7} className="px-6 py-12 text-center text-zinc-400">
                                Aucun client ne correspond aux critères de recherche.
                            </td>
                        </tr>
                    ) : (
                        clients.map((client) => (
                            <tr key={client.id} className="transition hover:bg-zinc-50">
                                <td className="px-6 py-4">
                                    <span className="font-semibold text-zinc-900">
                                        {client.firstName} {client.lastName}
                                    </span>
                                </td>
                                <td className="px-6 py-4 text-zinc-600">
                                    {client.email ?? <span className="text-zinc-300">—</span>}
                                </td>
                                <td className="px-6 py-4 text-zinc-600">
                                    {client.phone ?? <span className="text-zinc-300">—</span>}
                                </td>
                                <td className="px-6 py-4">
                                    {client.cin ? (
                                        <span className="inline-flex items-center rounded-lg bg-zinc-100 px-3 py-1 text-sm font-bold text-zinc-900">
                                            {client.cin}
                                        </span>
                                    ) : (
                                        <span className="text-zinc-300">—</span>
                                    )}
                                </td>
                                <td className="px-6 py-4 text-zinc-600">
                                    {client.nationality ?? <span className="text-zinc-300">—</span>}
                                </td>
                                <td className="px-6 py-4">
                                    <ClientStatusBadge active={client.active} />
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex items-center justify-end gap-2">
                                        <Link
                                            href={`/clients/${client.id}`}
                                            className="flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-900"
                                            title="Voir le détail"
                                        >
                                            <Eye size={16} />
                                        </Link>
                                        <Link
                                            href={`/clients/${client.id}/edit`}
                                            className="flex h-8 w-8 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-100 hover:text-zinc-900"
                                            title="Modifier"
                                        >
                                            <Pencil size={16} />
                                        </Link>
                                        {client.active ? (
                                            <button
                                                onClick={() => onDeactivateClick(client)}
                                                className="flex h-8 w-8 items-center justify-center rounded-lg text-orange-500 transition hover:bg-orange-50 hover:text-orange-600"
                                                title="Désactiver le client"
                                            >
                                                <Power size={16} />
                                            </button>
                                        ) : (
                                            <button
                                                onClick={() => onActivateClick?.(client)}
                                                className="flex h-8 w-8 items-center justify-center rounded-lg text-emerald-600 transition hover:bg-emerald-50 hover:text-emerald-700"
                                                title="Réactiver le client"
                                            >
                                                <RefreshCcw size={16} />
                                            </button>
                                        )}
                                    </div>
                                </td>
                            </tr>
                        ))
                    )}
                </tbody>
            </table>
        </div>
    );
}
