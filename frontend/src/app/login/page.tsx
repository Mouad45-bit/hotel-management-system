"use client";

import { useState, type FormEvent } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { Building2, AlertCircle, LogIn } from "lucide-react";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsInput } from "@/components/hms/HmsField";

export default function LoginPage() {
    const { login } = useAuth();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError("");
        setIsLoading(true);
        try {
            await login({ username, password });
        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur de connexion");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex min-h-screen items-center justify-center bg-[var(--hms-page)] px-4">
            <div className="w-full max-w-md">
                <div className="mb-8 flex flex-col items-center">
                    <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--hms-primary)] text-white">
                        <Building2 className="h-8 w-8" strokeWidth={1.8} />
                    </div>
                    <h1 className="text-2xl font-bold text-[var(--hms-text)]">HMS</h1>
                    <p className="mt-1 text-sm text-[var(--hms-text-muted)]">Maison Lumière · Back-office</p>
                </div>

                <form
                    onSubmit={handleSubmit}
                    className="space-y-6 rounded-[20px] border border-[var(--hms-soft-border)] bg-[var(--hms-surface)] p-8 shadow-[0_16px_40px_rgba(13,9,7,0.03)]"
                >
                    {error && (
                        <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                            <AlertCircle className="h-5 w-5 shrink-0" strokeWidth={1.8} />
                            <span className="text-sm font-medium">{error}</span>
                        </div>
                    )}

                    <HmsInput
                        id="username"
                        label="Nom d'utilisateur"
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        autoFocus
                        placeholder="admin"
                    />

                    <HmsInput
                        id="password"
                        label="Mot de passe"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        placeholder="••••••••"
                    />

                    <HmsButton type="submit" disabled={isLoading} className="w-full">
                        <LogIn className="h-[18px] w-[18px]" strokeWidth={1.8} aria-hidden="true" />
                        {isLoading ? "Connexion..." : "Se connecter"}
                    </HmsButton>
                </form>

                <p className="mt-6 text-center text-xs text-[var(--hms-text-muted)]">
                    Maison Lumière · HMS &copy; 2026
                </p>
            </div>
        </div>
    );
}
