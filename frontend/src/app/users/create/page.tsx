'use client';

import { useState, FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageHeader } from '@/components/layout/PageHeader';
import { AuthService } from '@/services/auth.service';
import { AlertCircle } from 'lucide-react';

const ROLES = [
    { value: 'ADMIN', label: 'Admin' },
    { value: 'MANAGER', label: 'Manager' },
    { value: 'RECEPTIONIST', label: 'Réceptionniste' },
    { value: 'HOUSEKEEPING_AGENT', label: 'Agent Housekeeping' },
    { value: 'HR', label: 'Ressources Humaines' },
];

const fieldClass = 'w-full rounded-xl border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-zinc-900 focus:ring-2 focus:ring-zinc-100';
const labelClass = 'mb-2 block text-sm font-semibold text-zinc-900';

export default function CreateUserPage() {
    const router = useRouter();
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [form, setForm] = useState({ username: '', email: '', password: '', firstName: '', lastName: '', role: 'RECEPTIONIST' });

    const set = (field: string, value: string) => setForm((prev) => ({ ...prev, [field]: value }));

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);
        try {
            await AuthService.createUser(form);
            router.push('/users');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <AppLayout>
            <PageHeader
                backHref="/users"
                eyebrow="Création"
                title="Nouvel utilisateur"
                description="Créez un nouveau compte utilisateur avec un rôle et des identifiants de connexion."
            />

            <form onSubmit={handleSubmit} className="space-y-6">
                {error && (
                    <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                        <AlertCircle size={20} />
                        <span className="text-sm font-medium">{error}</span>
                    </div>
                )}

                <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                    <h2 className="text-2xl font-bold text-zinc-950">Informations du compte</h2>

                    <div className="mt-8 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
                        <div>
                            <label className={labelClass}>Prénom <span className="text-zinc-400">*</span></label>
                            <input type="text" required value={form.firstName} onChange={(e) => set('firstName', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Nom <span className="text-zinc-400">*</span></label>
                            <input type="text" required value={form.lastName} onChange={(e) => set('lastName', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Nom d&apos;utilisateur <span className="text-zinc-400">*</span></label>
                            <input type="text" required value={form.username} onChange={(e) => set('username', e.target.value)} className={fieldClass} placeholder="ex: jdupont" />
                        </div>
                        <div>
                            <label className={labelClass}>Email</label>
                            <input type="email" value={form.email} onChange={(e) => set('email', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Mot de passe <span className="text-zinc-400">*</span></label>
                            <input type="password" required minLength={6} value={form.password} onChange={(e) => set('password', e.target.value)} className={fieldClass} />
                        </div>
                        <div>
                            <label className={labelClass}>Rôle <span className="text-zinc-400">*</span></label>
                            <select value={form.role} onChange={(e) => set('role', e.target.value)} className={fieldClass}>
                                {ROLES.map((r) => (
                                    <option key={r.value} value={r.value}>{r.label}</option>
                                ))}
                            </select>
                        </div>
                    </div>
                </div>

                <div className="flex justify-end gap-3">
                    <button type="button" onClick={() => router.push('/users')} disabled={isLoading}
                        className="rounded-2xl border border-zinc-200 bg-white px-6 py-3 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-50">
                        Annuler
                    </button>
                    <button type="submit" disabled={isLoading}
                        className="rounded-2xl bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:bg-zinc-800 disabled:opacity-50">
                        {isLoading ? 'Création...' : 'Créer l\'utilisateur'}
                    </button>
                </div>
            </form>
        </AppLayout>
    );
}
