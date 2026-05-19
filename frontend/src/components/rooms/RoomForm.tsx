import { useState } from 'react';
import { ROOM_TYPES, ROOM_STATUSES, ROOM_TYPE_LABELS, ROOM_STATUS_LABELS } from '@/types/room';
import { roomSchema, RoomFormValues, DEFAULT_ROOM_FORM_VALUES } from '@/schemas/room.schema';

interface RoomFormProps {
    initialData?: Partial<RoomFormValues>;
    onSubmit: (data: RoomFormValues) => void;
    onCancel: () => void;
}

export function RoomForm({ initialData, onSubmit, onCancel }: RoomFormProps) {
    // 1. Initialisation propre avec les valeurs par défaut du schéma
    const [formData, setFormData] = useState<RoomFormValues>({
        ...DEFAULT_ROOM_FORM_VALUES,
        ...initialData
    });

    const [errors, setErrors] = useState<Record<string, string>>({});

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;

        // On gère dynamiquement la conversion pour tous les champs numériques requis
        const numericFields = ['pricePerNight', 'floor', 'capacity'];
        const parsedValue = numericFields.includes(name) ? Number(value) : value;

        setFormData(prev => ({ ...prev, [name]: parsedValue }));

        if (errors[name]) {
            setErrors(prev => ({ ...prev, [name]: '' }));
        }
    };

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        const validationResult = roomSchema.safeParse(formData);

        if (!validationResult.success) {
            const fieldErrors: Record<string, string> = {};
            validationResult.error.issues.forEach(issue => {
                const fieldName = issue.path[0].toString();
                if (!fieldErrors[fieldName]) {
                    fieldErrors[fieldName] = issue.message;
                }
            });
            setErrors(fieldErrors);
            return;
        }

        setErrors({});
        onSubmit(validationResult.data);
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6 rounded-xl bg-white p-6 shadow-sm ring-1 ring-zinc-200">
            <h3 className="text-lg font-medium text-zinc-900">
                {initialData ? "Modifier la chambre" : "Ajouter une chambre"}
            </h3>

            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
                {/* Champ Numéro */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Numéro de chambre</label>
                    <input
                        type="text"
                        name="number"
                        value={formData.number}
                        onChange={handleChange}
                        placeholder="ex: 101"
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    />
                    {errors.number && <p className="mt-1 text-sm text-red-600">{errors.number}</p>}
                </div>

                {/* Champ Étage */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Étage</label>
                    <input
                        type="number"
                        name="floor"
                        value={formData.floor}
                        onChange={handleChange}
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    />
                    {errors.floor && <p className="mt-1 text-sm text-red-600">{errors.floor}</p>}
                </div>

                {/* Champ Capacité */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Capacité (personnes)</label>
                    <input
                        type="number"
                        name="capacity"
                        value={formData.capacity}
                        onChange={handleChange}
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    />
                    {errors.capacity && <p className="mt-1 text-sm text-red-600">{errors.capacity}</p>}
                </div>

                {/* Champ Prix */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Prix par nuit (€)</label>
                    <input
                        type="number"
                        name="pricePerNight" // Correction du nom
                        value={formData.pricePerNight}
                        onChange={handleChange}
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    />
                    {errors.pricePerNight && <p className="mt-1 text-sm text-red-600">{errors.pricePerNight}</p>}
                </div>

                {/* Champ Type (Dynamique) */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Type de chambre</label>
                    <select
                        name="type"
                        value={formData.type}
                        onChange={handleChange}
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    >
                        {ROOM_TYPES.map(t => (
                            <option key={t} value={t}>{ROOM_TYPE_LABELS[t]}</option>
                        ))}
                    </select>
                    {errors.type && <p className="mt-1 text-sm text-red-600">{errors.type}</p>}
                </div>

                {/* Champ Statut (Dynamique) */}
                <div>
                    <label className="block text-sm font-medium text-zinc-700">Statut</label>
                    <select
                        name="status"
                        value={formData.status}
                        onChange={handleChange}
                        className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                    >
                        {ROOM_STATUSES.map(s => (
                            <option key={s} value={s}>{ROOM_STATUS_LABELS[s]}</option>
                        ))}
                    </select>
                    {errors.status && <p className="mt-1 text-sm text-red-600">{errors.status}</p>}
                </div>
            </div>

            {/* Champ Description */}
            <div>
                <label className="block text-sm font-medium text-zinc-700">Description</label>
                <textarea
                    name="description"
                    value={formData.description || ''} // Fallback pour éviter l'erreur d'uncontrolled input
                    onChange={handleChange}
                    rows={3}
                    placeholder="Description des équipements..."
                    className="mt-1 block w-full rounded-md border border-zinc-300 px-3 py-2 text-zinc-900 shadow-sm focus:border-stone-900 focus:outline-none focus:ring-1 focus:ring-stone-900"
                />
                {errors.description && <p className="mt-1 text-sm text-red-600">{errors.description}</p>}
            </div>

            {/* Boutons d'action */}
            <div className="flex justify-end gap-3 border-t border-zinc-200 pt-4 mt-6">
                <button
                    type="button"
                    onClick={onCancel}
                    className="rounded-md border border-zinc-200 bg-white px-4 py-2 text-sm font-medium text-zinc-900 hover:bg-zinc-50"
                >
                    Annuler
                </button>
                <button
                    type="submit"
                    className="rounded-md bg-stone-900 px-4 py-2 text-sm font-medium text-white hover:bg-stone-800"
                >
                    Sauvegarder
                </button>
            </div>
        </form>
    );
}
