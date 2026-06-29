"use client";

import { useState, useEffect, type FormEvent } from "react";
import { AlertCircle } from "lucide-react";
import { reservationSchema, type ReservationFormValues } from "@/schemas/reservation.schema";
import type { Room } from "@/types/room";
import type { Client } from "@/types/client";
import { RoomService } from "@/services/room.service";
import { ClientService } from "@/services/client.service";
import { HmsButton } from "@/components/hms/HmsButton";
import { HmsInput, HmsSelect, HmsTextarea } from "@/components/hms/HmsField";
import { HmsCard } from "@/components/hms/HmsCard";

interface ReservationFormProps {
    initialData?: Partial<ReservationFormValues>;
    onSubmit: (data: ReservationFormValues) => Promise<void>;
    onCancel: () => void;
    isLoading?: boolean;
    submitLabel?: string;
    lockRoomAndClient?: boolean;
    requireAvailableRoom?: boolean;
}

export function ReservationForm({
    initialData,
    onSubmit,
    onCancel,
    isLoading,
    submitLabel = "Créer",
    lockRoomAndClient,
    requireAvailableRoom = false,
}: ReservationFormProps) {
    const [formData, setFormData] = useState<Partial<ReservationFormValues>>(
        initialData ?? { roomId: 0, clientId: 0, checkInDate: "", checkOutDate: "", notes: "" }
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
        if (errors[field]) setErrors((prev) => ({ ...prev, [field]: "" }));
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

        const room = rooms.find((r) => r.id === validation.data.roomId);
        if (requireAvailableRoom && room && (!room.active || room.status !== "AVAILABLE")) {
            setErrors({ roomId: "Seules les chambres disponibles peuvent être réservées." });
            return;
        }

        try {
            await onSubmit(validation.data);
        } catch (err) {
            setErrors({ global: err instanceof Error ? err.message : "Erreur inattendue" });
        }
    };

    const nights = formData.checkInDate && formData.checkOutDate
        ? Math.max(0, Math.ceil((new Date(formData.checkOutDate).getTime() - new Date(formData.checkInDate).getTime()) / (1000 * 60 * 60 * 24)))
        : 0;

    const selectedRoom = rooms.find((r) => r.id === formData.roomId);
    const selectedRoomUnavailable = Boolean(requireAvailableRoom && selectedRoom && (!selectedRoom.active || selectedRoom.status !== "AVAILABLE"));
    const estimatedPrice = selectedRoom ? nights * selectedRoom.pricePerNight : 0;

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            {errors.global && (
                <div className="flex items-center gap-3 rounded-xl bg-red-50 p-4 text-red-700">
                    <AlertCircle className="h-5 w-5 shrink-0" strokeWidth={1.8} />
                    <span className="text-sm font-medium">{errors.global}</span>
                </div>
            )}

            <HmsCard>
                <h2 className="text-lg font-bold text-[var(--hms-text)]">Détails de la réservation</h2>

                <div className="mt-6 grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2">
                    <HmsSelect
                        id="roomId"
                        label="Chambre *"
                        value={String(formData.roomId ?? 0)}
                        onChange={(e) => handleChange("roomId", Number(e.target.value))}
                        disabled={lockRoomAndClient}
                        error={errors.roomId}
                    >
                        <option value="0">Sélectionner une chambre</option>
                        {rooms
                            .filter((r) => r.active && (r.status === "AVAILABLE" || (!requireAvailableRoom && r.id === formData.roomId)))
                            .map((room) => (
                                <option key={room.id} value={room.id}>
                                    Chambre {room.number} — {room.type} — {room.pricePerNight} DH/nuit
                                </option>
                            ))}
                    </HmsSelect>

                    <HmsSelect
                        id="clientId"
                        label="Client *"
                        value={String(formData.clientId ?? 0)}
                        onChange={(e) => handleChange("clientId", Number(e.target.value))}
                        disabled={lockRoomAndClient}
                        error={errors.clientId}
                    >
                        <option value="0">Sélectionner un client</option>
                        {clients
                            .filter((c) => c.active)
                            .map((client) => (
                                <option key={client.id} value={client.id}>
                                    {client.firstName} {client.lastName} {client.cin ? `— ${client.cin}` : ""}
                                </option>
                            ))}
                    </HmsSelect>

                    <HmsInput
                        id="checkInDate"
                        label="Date d'arrivée *"
                        type="date"
                        value={formData.checkInDate ?? ""}
                        onChange={(e) => handleChange("checkInDate", e.target.value)}
                        error={errors.checkInDate}
                    />

                    <HmsInput
                        id="checkOutDate"
                        label="Date de départ *"
                        type="date"
                        value={formData.checkOutDate ?? ""}
                        onChange={(e) => handleChange("checkOutDate", e.target.value)}
                        error={errors.checkOutDate}
                    />
                </div>

                <div className="mt-5">
                    <HmsTextarea
                        id="notes"
                        label="Notes"
                        rows={3}
                        placeholder="Notes ou demandes spéciales..."
                        value={formData.notes ?? ""}
                        onChange={(e) => handleChange("notes", e.target.value)}
                    />
                </div>

                {nights > 0 && selectedRoom && (
                    <div className="mt-6 rounded-xl bg-slate-50 p-4 ring-1 ring-inset ring-[var(--hms-soft-border)]">
                        <p className="text-xs font-bold uppercase tracking-wide text-[var(--hms-text-muted)]">Estimation</p>
                        <p className="mt-1 text-lg font-bold text-[var(--hms-text)]">
                            {nights} nuit{nights > 1 ? "s" : ""} × {selectedRoom.pricePerNight} DH ={" "}
                            <span className="text-emerald-600">{estimatedPrice} DH</span>
                        </p>
                    </div>
                )}

                {selectedRoomUnavailable && (
                    <div className="mt-5 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-800">
                        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
                        <span className="font-medium">
                            Cette chambre n’est pas disponible. Sélectionnez une chambre disponible pour créer une réservation.
                        </span>
                    </div>
                )}
            </HmsCard>

            <div className="flex justify-end gap-3">
                <HmsButton type="button" variant="secondary" onClick={onCancel} disabled={isLoading}>
                    Annuler
                </HmsButton>
                <HmsButton type="submit" disabled={isLoading}>
                    {isLoading ? "Enregistrement..." : submitLabel}
                </HmsButton>
            </div>
        </form>
    );
}
