'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { UserRoleBadge } from '@/components/users/UserRoleBadge';
import { ClientStatusBadge } from '@/components/clients/ClientStatusBadge';
import { AuthService } from '@/services/auth.service';
import { User } from '@/types/user';
import { Plus, RefreshCcw, AlertCircle, Eye } from 'lucide-react';

export default function UsersPage() {
    const [users, setUsers] = useState<User[]>([]);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        AuthService.getUsers()
            .then(setUsers)
            .catch((err) => setError(err instanceof Error ? err.message : 'Erreur'))
            .finally(() => setLoading(false));
    }, []);

    return (
        <AppLayout>
            <PageHeader
                title="Gestion des utilisateurs"
                description="Créez et gérez les comptes utilisateurs du système. Chaque utilisateur possède un rôle qui détermine ses permissions."
                actions={
                    <Link
                        href="/users/create"
                        className="inline-flex items-center gap-2 rounded-2xl bg-zinc-900 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-zinc-800"
                    >
                        <Plus size={18} />
                        Nouvel utilisateur
                    </Link>
                }
            />

            {error ? (
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <div>
                        <p className="font-semibold text-red-700">Impossible de charger les utilisateurs</p>
                        <p className="mt-1 text-sm text-red-600">{error}</p>
                    </div>
                </div>
            ) : isLoading ? (
                <div className="flex items-center justify-center py-24 text-zinc-400 bg-white rounded-2xl ring-1 ring-zinc-200">
                    <RefreshCcw size={18} className="mr-2 animate-spin" />
                    Chargement...
                </div>
            ) : (
                <div className="overflow-hidden rounded-2xl bg-white shadow-sm ring-1 ring-zinc-200">
                    <table className="min-w-full divide-y divide-zinc-100">
                        <thead className="bg-zinc-50">
                            <tr>
                                <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-zinc-500">Utilisateur</th>
                                <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-zinc-500">Email</th>
                                <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-zinc-500">Rôle</th>
                                <th className="px-6 py-3.5 text-left text-xs font-semibold uppercase tracking-wider text-zinc-500">Statut</th>
                                <th className="px-6 py-3.5 text-right text-xs font-semibold uppercase tracking-wider text-zinc-500">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-50">
                            {users.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-6 py-12 text-center text-sm text-zinc-500">
                                        Aucun utilisateur trouvé.
                                    </td>
                                </tr>
                            ) : users.map((u) => (
                                <tr key={u.id} className="transition hover:bg-zinc-50">
                                    <td className="px-6 py-4">
                                        <p className="text-sm font-semibold text-zinc-900">{u.firstName} {u.lastName}</p>
                                        <p className="text-xs text-zinc-500">@{u.username}</p>
                                    </td>
                                    <td className="px-6 py-4 text-sm text-zinc-600">{u.email ?? '—'}</td>
                                    <td className="px-6 py-4"><UserRoleBadge role={u.role} /></td>
                                    <td className="px-6 py-4"><ClientStatusBadge active={u.active} /></td>
                                    <td className="px-6 py-4 text-right">
                                        <Link
                                            href={`/users/${u.id}/edit`}
                                            className="inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-sm font-medium text-zinc-600 transition hover:bg-zinc-100"
                                        >
                                            <Eye size={15} />
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </AppLayout>
    );
}
