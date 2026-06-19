'use client';

import { useState, FormEvent } from 'react';
import { roomSchema, RoomFormValues } from '@/schemas/room.schema';
import { RoomType } from '@/types/room';
import { AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

const TYPE_OPTIONS: Record<RoomType, string> = {
    SINGLE: "Single", DOUBLE: "Double", TWIN: "Twin",
    SUITE: "Suite", FAMILY: "Family", DELUXE: "Deluxe",
};

interface RoomFormProps {
    initialData?: Partial<RoomFormValues>;
    onSubmit: (data: RoomFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
}

const fieldClass = (error?: string) =>
    cn(
        "w-full rounded-xl border bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:ring-2",
        error
            ? "border-red-300 focus:border-red-500 focus:ring-red-100"
            : "border-zinc-200 focus:border-zinc-900 focus:ring-zinc-100"
    );

const labelClass = "mb-2 block text-sm font-semibold text-zinc-900";

export function RoomForm({ initialData, onSubmit, onCancel, isLoading, submitLabel = "Créer" }: RoomFormProps) {
    const [formData, setFormData] = useState<Partial<RoomFormValues>>(
        initialData ?? {
            type: 'DOUBLE',
            active: true,
            status: 'AVAILABLE',
            number: '',
            description: '',
        }
    );

    const [errors, setErrors] = useState<Record<string, string>>({});

    const handleChange = (field: keyof RoomFormValues, value: string | number | boolean) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: '' }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrors({});

        const validation = roomSchema.safeParse(formData);
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

            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <h2 className="text-2xl font-bold text-zinc-950">Informations générales</h2>

                <div className="mt-8 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
                    {/* Numéro */}
                    <div>
                        <label className={labelClass}>
                            Numéro de chambre <span className="text-zinc-400">*</span>
                        </label>
                        <input
                            type="text"
                            placeholder="Exemple : 101"
                            value={formData.number ?? ''}
                            onChange={(e) => handleChange('number', e.target.value)}
                            className={fieldClass(errors.number)}
                        />
                        {errors.number && <p className="mt-1.5 text-xs text-red-600">{errors.number}</p>}
                    </div>

                    {/* Type */}
                    <div>
                        <label className={labelClass}>
                            Type de chambre <span className="text-zinc-400">*</span>
                        </label>
                        <select
                            value={formData.type ?? ''}
                            onChange={(e) => handleChange('type', e.target.value)}
                            className={fieldClass()}
                        >
                            {(Object.keys(TYPE_OPTIONS) as RoomType[]).map((t) => (
                                <option key={t} value={t}>{TYPE_OPTIONS[t]}</option>
                            ))}
                        </select>
                    </div>

                    {/* Étage */}
                    <div>
                        <label className={labelClass}>
                            Étage <span className="text-zinc-400">*</span>
                        </label>
                        <input
                            type="number"
                            min={0}
                            placeholder="Exemple : 1"
                            value={formData.floor ?? ''}
                            onChange={(e) => handleChange('floor', Number(e.target.value))}
                            className={fieldClass(errors.floor)}
                        />
                        {errors.floor && <p className="mt-1.5 text-xs text-red-600">{errors.floor}</p>}
                    </div>

                    {/* Capacité */}
                    <div>
                        <label className={labelClass}>
                            Capacité <span className="text-zinc-400">*</span>
                        </label>
                        <input
                            type="number"
                            min={1}
                            placeholder="Exemple : 2"
                            value={formData.capacity ?? ''}
                            onChange={(e) => handleChange('capacity', Number(e.target.value))}
                            className={fieldClass(errors.capacity)}
                        />
                        {errors.capacity && <p className="mt-1.5 text-xs text-red-600">{errors.capacity}</p>}
                    </div>

                    {/* Prix par nuit */}
                    <div>
                        <label className={labelClass}>
                            Prix par nuit <span className="text-zinc-400">*</span>
                        </label>
                        <input
                            type="number"
                            min={0}
                            step="0.01"
                            placeholder="Exemple : 500"
                            value={formData.pricePerNight ?? ''}
                            onChange={(e) => handleChange('pricePerNight', Number(e.target.value))}
                            className={fieldClass(errors.pricePerNight)}
                        />
                        {errors.pricePerNight && <p className="mt-1.5 text-xs text-red-600">{errors.pricePerNight}</p>}
                    </div>

                    {/* Activation administrative */}
                    <div>
                        <label className={labelClass}>
                            Activation administrative <span className="text-zinc-400">*</span>
                        </label>
                        <select
                            value={formData.active === false ? 'false' : 'true'}
                            onChange={(e) => handleChange('active', e.target.value === 'true')}
                            className={fieldClass()}
                        >
                            <option value="true">Active</option>
                            <option value="false">Inactive</option>
                        </select>
                    </div>
                </div>

                {/* Description (pleine largeur) */}
                <div className="mt-6">
                    <label className={labelClass}>Description</label>
                    <textarea
                        rows={4}
                        value={formData.description ?? ''}
                        onChange={(e) => handleChange('description', e.target.value)}
                        className={cn(fieldClass(), "resize-none")}
                        placeholder="Décrivez brièvement la chambre..."
                    />
                </div>
            </div>

            {/* Actions hors carte, alignées à droite */}
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
