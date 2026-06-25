'use client';

import { useState, FormEvent } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Building2, AlertCircle, LogIn } from 'lucide-react';

export default function LoginPage() {
    const { login } = useAuth();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);
        try {
            await login({ username, password });
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Erreur de connexion');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex min-h-screen items-center justify-center bg-zinc-50 px-4">
            <div className="w-full max-w-md">
                <div className="flex flex-col items-center mb-8">
                    <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-zinc-900 text-white mb-4">
                        <Building2 className="h-8 w-8" />
                    </div>
                    <h1 className="text-2xl font-bold text-zinc-950">HMS</h1>
                    <p className="mt-1 text-sm text-zinc-500">Connectez-vous pour accéder au système</p>
                </div>

                <form onSubmit={handleSubmit} className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200 space-y-6">
                    {error && (
                        <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                            <AlertCircle size={20} />
                            <span className="text-sm font-medium">{error}</span>
                        </div>
                    )}

                    <div>
                        <label className="mb-2 block text-sm font-semibold text-zinc-900">
                            Nom d&apos;utilisateur
                        </label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            autoFocus
                            className="w-full rounded-xl border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-zinc-900 focus:ring-2 focus:ring-zinc-100"
                            placeholder="admin"
                        />
                    </div>

                    <div>
                        <label className="mb-2 block text-sm font-semibold text-zinc-900">
                            Mot de passe
                        </label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="w-full rounded-xl border border-zinc-200 bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:border-zinc-900 focus:ring-2 focus:ring-zinc-100"
                            placeholder="••••••••"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={isLoading}
                        className="w-full inline-flex items-center justify-center gap-2 rounded-2xl bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:bg-zinc-800 disabled:opacity-50"
                    >
                        <LogIn size={18} />
                        {isLoading ? 'Connexion...' : 'Se connecter'}
                    </button>
                </form>

                <p className="mt-6 text-center text-xs text-zinc-400">
                    Hotel Management System &copy; 2026
                </p>
            </div>
        </div>
    );
}
