import { z } from "zod";

export const reservationSchema = z.object({
    roomId: z.number({ required_error: "La chambre est obligatoire" }).min(1, "La chambre est obligatoire"),
    clientId: z.number({ required_error: "Le client est obligatoire" }).min(1, "Le client est obligatoire"),
    checkInDate: z.string().min(1, "La date d'arrivée est obligatoire"),
    checkOutDate: z.string().min(1, "La date de départ est obligatoire"),
    notes: z.string().optional().or(z.literal("")),
}).refine(
    (data) => {
        if (!data.checkInDate || !data.checkOutDate) return true;
        return new Date(data.checkOutDate) > new Date(data.checkInDate);
    },
    {
        message: "La date de départ doit être après la date d'arrivée",
        path: ["checkOutDate"],
    }
);

export type ReservationFormValues = z.infer<typeof reservationSchema>;
