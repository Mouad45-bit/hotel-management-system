'use client';

import { useState, useEffect, FormEvent } from 'react';
import { reservationSchema, ReservationFormValues } from '@/schemas/reservation.schema';
import { Room } from '@/types/room';
import { Client } from '@/types/client';
import { RoomService } from '@/services/room.service';
import { ClientService } from '@/services/client.service';
import { AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ReservationFormProps {
    initialData?: Partial<ReservationFormValues>;
    onSubmit: (data: ReservationFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
    lockRoomAndClient?: boolean;
}

const fieldClass = (error?: string) =>
    cn(
        'w-full rounded-xl border bg-white px-4 py-3 text-sm text-zinc-900 outline-none transition placeholder:text-zinc-400 focus:ring-2',
        error
            ? 'border-red-300 focus:border-red-500 focus:ring-red-100'
            : 'border-zinc-200 focus:border-zinc-900 focus:ring-zinc-100'
    );

const labelClass = 'mb-2 block text-sm font-semibold text-zinc-900';

export function ReservationForm({ initialData, onSubmit, onCancel, isLoading, submitLabel = 'Créer', lockRoomAndClient }: ReservationFormProps) {
    const [formData, setFormData] = useState<Partial<ReservationFormValues>>(
        initialData ?? { roomId: 0, clientId: 0, checkInDate: '', checkOutDate: '', notes: '' }
    );
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [rooms, setRooms] = useState<Room[]>([]);
    const [clients, setClients] = useState<Client[]>([]);

    useEffect(() => {
        RoomService.getRooms().then(setRooms).catch(() => {});
        ClientService.getClients().then(setClients).catch(() => {});
    }, []);

    const handleChange = (field: keyof ReservationFormValues, value: string | number) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: '' }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setErrors({});

        const validation = reservationSchema.safeParse(formData);
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

    const nights = formData.checkInDate && formData.checkOutDate
        ? Math.max(0, Math.ceil((new Date(formData.checkOutDate).getTime() - new Date(formData.checkInDate).getTime()) / (1000 * 60 * 60 * 24)))
        : 0;

    const selectedRoom = rooms.find(r => r.id === formData.roomId);
    const estimatedPrice = selectedRoom ? nights * selectedRoom.pricePerNight : 0;

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            {errors.global && (
                <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                    <AlertCircle size={20} />
                    <span className="text-sm font-medium">{errors.global}</span>
                </div>
            )}

            <div className="rounded-3xl bg-white p-8 shadow-sm ring-1 ring-zinc-200">
                <h2 className="text-2xl font-bold text-zinc-950">Détails de la réservation</h2>

                <div className="mt-8 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
                    <div>
                        <label className={labelClass}>Chambre <span className="text-zinc-400">*</span></label>
                        <select
                            value={formData.roomId ?? 0}
                            onChange={(e) => handleChange('roomId', Number(e.target.value))}
                            className={fieldClass(errors.roomId)}
                            disabled={lockRoomAndClient}
                        >
                            <option value={0}>Sélectionner une chambre</option>
                            {rooms.filter(r => r.active && (r.status === 'AVAILABLE' || r.id === formData.roomId)).map((room) => (
                                <option key={room.id} value={room.id}>
                                    Chambre {room.number} — {room.type} — {room.pricePerNight} DH/nuit
                                </option>
                            ))}
                        </select>
                        {errors.roomId && <p className="mt-1.5 text-xs text-red-600">{errors.roomId}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Client <span className="text-zinc-400">*</span></label>
                        <select
                            value={formData.clientId ?? 0}
                            onChange={(e) => handleChange('clientId', Number(e.target.value))}
                            className={fieldClass(errors.clientId)}
                            disabled={lockRoomAndClient}
                        >
                            <option value={0}>Sélectionner un client</option>
                            {clients.filter(c => c.active).map((client) => (
                                <option key={client.id} value={client.id}>
                                    {client.firstName} {client.lastName} {client.cin ? `— ${client.cin}` : ''}
                                </option>
                            ))}
                        </select>
                        {errors.clientId && <p className="mt-1.5 text-xs text-red-600">{errors.clientId}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Date d&apos;arrivée <span className="text-zinc-400">*</span></label>
                        <input
                            type="date"
                            value={formData.checkInDate ?? ''}
                            onChange={(e) => handleChange('checkInDate', e.target.value)}
                            className={fieldClass(errors.checkInDate)}
                        />
                        {errors.checkInDate && <p className="mt-1.5 text-xs text-red-600">{errors.checkInDate}</p>}
                    </div>

                    <div>
                        <label className={labelClass}>Date de départ <span className="text-zinc-400">*</span></label>
                        <input
                            type="date"
                            value={formData.checkOutDate ?? ''}
                            onChange={(e) => handleChange('checkOutDate', e.target.value)}
                            className={fieldClass(errors.checkOutDate)}
                        />
                        {errors.checkOutDate && <p className="mt-1.5 text-xs text-red-600">{errors.checkOutDate}</p>}
                    </div>
                </div>

                <div className="mt-6">
                    <label className={labelClass}>Notes</label>
                    <textarea
                        rows={3}
                        placeholder="Notes ou demandes spéciales..."
                        value={formData.notes ?? ''}
                        onChange={(e) => handleChange('notes', e.target.value)}
                        className={cn(fieldClass(), 'resize-none')}
                    />
                </div>

                {nights > 0 && selectedRoom && (
                    <div className="mt-6 rounded-2xl border border-zinc-100 bg-zinc-50 p-5">
                        <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Estimation</p>
                        <p className="mt-1 text-lg font-bold text-zinc-900">
                            {nights} nuit{nights > 1 ? 's' : ''} × {selectedRoom.pricePerNight} DH = <span className="text-emerald-600">{estimatedPrice} DH</span>
                        </p>
                    </div>
                )}
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
