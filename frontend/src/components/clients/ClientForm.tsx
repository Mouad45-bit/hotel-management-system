'use client';

import { useState, FormEvent } from 'react';
import { clientSchema, ClientFormValues } from '@/schemas/client.schema';
import { AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ClientFormProps {
    initialData?: Partial<ClientFormValues>;
    onSubmit: (data: ClientFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
}

const fieldClass = (error?: string) =>
    cn(
        'w-full rounded-xl border bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:ring-2',
        error
            ? 'border-red-300 focus:border-red-500 focus:ring-red-100'
            : 'border-zinc-200 focus:border-zinc-900 focus:ring-zinc-100'
    );

const labelClass = 'mb-2 block text-sm font-semibold text-zinc-900';

export function ClientForm({ initialData, onSubmit, onCancel, isLoading, submitLabel = 'Créer' }: ClientFormProps) {
    const [formData, setFormData] = useState<Partial<ClientFormValues>>(
        initialData ?? {
            firstName: '',
            lastName: '',
            email: '',
            phone: '',
            cin: '',
            passportNumber: '',
            nationality: '',
            address: '',
            birthDate: '',
        }
    );
    const [errors, setErrors] = useState<Record<string, string>>({});

    const handleChange = (field: keyof ClientFormValues, value: string) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: '' }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrors({});

        const validation = clientSchema.safeParse(formData);
        if (!validation.success) {
            const formattedErrors: Record<string, string> = {};
            validation.error.issues.forEach((issue) => {
                formattedErrors[String(issue.path[0])] = issue.message;
            });
            setErrors(formattedErrors);
            return;
        }

        try {
            await onSubmit(validation.data);
        } catch (err) {
            setErrors({ global: err instanceof Error ? err.message : 'Erreur inattendue' });
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            {errors.global && (
                <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                    <AlertCircle size={20} />
                    <span className="text-sm font-medium">{errors.global}</span>
                </div>
            )}

            {/* Section identité */}
            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <h2 className="text-2xl font-bold text-zinc-950">Informations personnelles</h2>

                <div className="mt-8 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
                    <div>
                        <label className={labelClass}>Prénom <span className="text-zinc-400">*</span></label>
                        <input
                            type="text"
                            placeholder="Exemple : Mohamed"
                            value={formData.firstName ?? ''}
                            onChange={(e) => handleChange('firstName', e.target.value)}
                            className={fieldClass(errors.firstName)}
                        />
                        {errors.firstName && <p className="mt-1.5 text-xs text-red-600">{errors.firstName}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Nom <span className="text-zinc-400">*</span></label>
                        <input
                            type="text"
                            placeholder="Exemple : Alaoui"
                            value={formData.lastName ?? ''}
                            onChange={(e) => handleChange('lastName', e.target.value)}
                            className={fieldClass(errors.lastName)}
                        />
                        {errors.lastName && <p className="mt-1.5 text-xs text-red-600">{errors.lastName}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Email</label>
                        <input
                            type="email"
                            placeholder="Exemple : client@email.com"
                            value={formData.email ?? ''}
                            onChange={(e) => handleChange('email', e.target.value)}
                            className={fieldClass(errors.email)}
                        />
                        {errors.email && <p className="mt-1.5 text-xs text-red-600">{errors.email}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Téléphone</label>
                        <input
                            type="tel"
                            placeholder="Exemple : +212 6XX XXX XXX"
                            value={formData.phone ?? ''}
                            onChange={(e) => handleChange('phone', e.target.value)}
                            className={fieldClass(errors.phone)}
                        />
                        {errors.phone && <p className="mt-1.5 text-xs text-red-600">{errors.phone}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>CIN</label>
                        <input
                            type="text"
                            placeholder="Exemple : AB123456"
                            value={formData.cin ?? ''}
                            onChange={(e) => handleChange('cin', e.target.value)}
                            className={fieldClass(errors.cin)}
                        />
                        {errors.cin && <p className="mt-1.5 text-xs text-red-600">{errors.cin}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Numéro de passeport</label>
                        <input
                            type="text"
                            placeholder="Exemple : AA1234567"
                            value={formData.passportNumber ?? ''}
                            onChange={(e) => handleChange('passportNumber', e.target.value)}
                            className={fieldClass(errors.passportNumber)}
                        />
                        {errors.passportNumber && <p className="mt-1.5 text-xs text-red-600">{errors.passportNumber}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Nationalité</label>
                        <input
                            type="text"
                            placeholder="Exemple : Marocaine"
                            value={formData.nationality ?? ''}
                            onChange={(e) => handleChange('nationality', e.target.value)}
                            className={fieldClass(errors.nationality)}
                        />
                    </div>

                    <div>
                        <label className={labelClass}>Date de naissance</label>
                        <input
                            type="date"
                            value={formData.birthDate ?? ''}
                            onChange={(e) => handleChange('birthDate', e.target.value)}
                            className={fieldClass(errors.birthDate)}
                        />
                        {errors.birthDate && <p className="mt-1.5 text-xs text-red-600">{errors.birthDate}</p>}
                    </div>
                </div>

                <div className="mt-6">
                    <label className={labelClass}>Adresse</label>
                    <textarea
                        rows={3}
                        placeholder="Adresse complète du client..."
                        value={formData.address ?? ''}
                        onChange={(e) => handleChange('address', e.target.value)}
                        className={cn(fieldClass(), 'resize-none')}
                    />
                </div>

                <p className="mt-4 text-xs text-zinc-400">
                    <span className="text-zinc-500 font-medium">*</span> Au moins un moyen d&apos;identification est requis : email, CIN, passeport ou téléphone.
                </p>
            </div>

            <div className="flex justify-end gap-3">
                <button
                    type="button"
                    onClick={onCancel}
                    disabled={isLoading}
                    className="rounded-2xl border border-zinc-200 bg-white px-6 py-3 text-sm font-semibold text-zinc-700 transition hover:bg-zinc-50 disabled:opacity-50"
                >
                    Annuler
                </button>
                <button
                    type="submit"
                    disabled={isLoading}
                    className="rounded-2xl bg-zinc-900 px-6 py-3 text-sm font-semibold text-white transition hover:bg-zinc-800 disabled:opacity-50"
                >
                    {isLoading ? 'Enregistrement...' : submitLabel}
                </button>
            </div>
        </form>
    );
}
