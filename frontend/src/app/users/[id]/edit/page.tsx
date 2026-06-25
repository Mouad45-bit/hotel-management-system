'use client';

import { useEffect, useState, FormEvent } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { UserRoleBadge } from '@/components/users/UserRoleBadge';
import { AuthService } from '@/services/auth.service';
import { User } from '@/types/user';
import { RefreshCcw, AlertCircle, Power, Check } from 'lucide-react';

const ROLES = [
    { value: 'ADMIN', label: 'Admin' },
    { value: 'MANAGER', label: 'Manager' },
    { value: 'RECEPTIONIST', label: 'Réceptionniste' },
    { value: 'HOUSEKEEPING_AGENT', label: 'Agent Housekeeping' },
    { value: 'HR', label: 'Ressources Humaines' },
];

const fieldClass = 'w-full rounded-xl border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-zinc-900 focus:ring-2 focus:ring-zinc-100';
const labelClass = 'mb-2 block text-sm font-semibold text-zinc-900';

export default function EditUserPage() {
    const router = useRouter();
    const params = useParams<{ id: string }>();
    const id = Number(params.id);

    const [user, setUser] = useState<User | null>(null);
    const [isLoading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSaving, setIsSaving] = useState(false);
    const [form, setForm] = useState({ email: '', firstName: '', lastName: '', role: '' });

    const fetchUser = () => {
        setLoading(true);
        AuthService.getUserById(id)
            .then((u) => {
                setUser(u);
                setForm({ email: u.email ?? '', firstName: u.firstName, lastName: u.lastName, role: u.role });
            })
            .catch((err) => setError(err instanceof Error ? err.message : 'Utilisateur introuvable'))
            .finally(() => setLoading(false));
    };

    useEffect(() => { fetchUser(); }, [id]);

    const set = (field: string, value: string) => setForm((prev) => ({ ...prev, [field]: value }));

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setIsSaving(true);
        try {
            await AuthService.updateUser(id, form);
            router.push('/users');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur');
        } finally {
            setIsSaving(false);
        }
    };

    const handleToggleActive = async () => {
        if (!user) return;
        try {
            if (user.active) {
                await AuthService.deactivateUser(id);
            } else {
                await AuthService.activateUser(id);
            }
            fetchUser();
        } catch (err) {
            alert(err instanceof Error ? err.message : 'Erreur');
        }
    };

    if (isLoading) {
        return (
            <AppLayout>
                <div className="flex items-center justify-center py-24 text-zinc-400">
                    <RefreshCcw size={18} className="mr-2 animate-spin" /> Chargement...
                </div>
            </AppLayout>
        );
    }

    if (error && !user) {
        return (
            <AppLayout>
                <div className="flex items-start gap-4 rounded-2xl border border-red-200 bg-red-50 p-6">
                    <AlertCircle className="mt-0.5 shrink-0 text-red-500" size={20} />
                    <p className="font-semibold text-red-700">{error}</p>
                </div>
            </AppLayout>
        );
    }

    return (
        <AppLayout>
            <PageHeader
                backHref="/users"
                eyebrow={`@${user?.username}`}
                title={`${user?.firstName} ${user?.lastName}`}
                description="Modifiez les informations, le rôle ou le statut de cet utilisateur."
                actions={
                    <button
                        onClick={handleToggleActive}
                        className={`inline-flex items-center gap-2 rounded-2xl px-4 py-2.5 text-sm font-semibold text-white transition ${
                            user?.active ? 'bg-orange-500 hover:bg-orange-600' : 'bg-emerald-500 hover:bg-emerald-600'
                        }`}
                    >
                        {user?.active ? <><Power size={16} /> Désactiver</> : <><Check size={16} /> Activer</>}
                    </button>
                }
            />

            <form onSubmit={handleSubmit} className="space-y-6">
                {error && (
                    <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                        <AlertCircle size={20} />
                        <span className="text-sm font-medium">{error}</span>
                    </div>
                )}

                <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                    <div className="flex items-center justify-between mb-8">
                        <h2 className="text-2xl font-bold text-zinc-950">Informations</h2>
                        {user && <UserRoleBadge role={user.role} />}
                    </div>

                    <div className="grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
                        <div>
                            <label className={labelClass}>Prénom</label>
                            <input type="text" value={form.firstName} onChange={(e) => set('firstName', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Nom</label>
                            <input type="text" value={form.lastName} onChange={(e) => set('lastName', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Email</label>
                            <input type="email" value={form.email} onChange={(e) => set('email', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Rôle</label>
                            <select value={form.role} onChange={(e) => set('role', e.target.value)} className={fieldClass}>
                                {ROLES.map((r) => (
                                    <option key={r.value} value={r.value}>{r.label}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                <div className="flex justify-end gap-3">
                    <button type="button" onClick={() => router.push('/users')} disabled={isSaving}
                        className="rounded-2xl border border-zinc-200 bg-white px-6 py-3 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-50">
                        Annuler
                    </button>
                    <button type="submit" disabled={isSaving}
                        className="rounded-2xl bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:bg-zinc-800 disabled:opacity-50">
                        {isSaving ? 'Enregistrement...' : 'Enregistrer'}
                    </button>
                </div>
            </form>
        </AppLayout>
    );
}
