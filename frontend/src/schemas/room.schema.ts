// frontend/src/schemas/room.schema.ts

import { z } from "zod";
import { ROOM_STATUSES, ROOM_TYPES } from "@/types/room";

export const roomTypeSchema
    = z.enum(ROOM_TYPES);

export const roomStatusSchema
    = z.enum(ROOM_STATUSES);

export const roomSchema
    = z.object({
    number: z
        .string()
        .trim()
        .min(1, "Le numéro de chambre est obligatoire")
        .max(10, "Le numéro de chambre ne doit pas dépasser 10 caractères"),

    floor: z.coerce
        .number()
        .int("L’étage doit être un nombre entier")
        .min(0, "L’étage doit être supérieur ou égal à 0")
        .max(50, "L’étage ne doit pas dépasser 50"),

    type: roomTypeSchema,

    pricePerNight: z.coerce
        .number()
        .min(0, "Le prix par nuit doit être supérieur ou égal à 0")
        .max(100000, "Le prix par nuit est trop élevé"),

    capacity: z.coerce
        .number()
        .int("La capacité doit être un nombre entier")
        .min(1, "La capacité doit être supérieure à 0")
        .max(20, "La capacité ne doit pas dépasser 20 personnes"),

    status: roomStatusSchema,

    description: z
        .string()
        .trim()
        .max(500, "La description ne doit pas dépasser 500 caractères")
        .optional(),
});

export type RoomFormValues = z.infer<typeof roomSchema>;

export const DEFAULT_ROOM_FORM_VALUES: RoomFormValues = {
    number: "",
    floor: 0,
    type: "SINGLE",
    pricePerNight: 0,
    capacity: 1,
    status: "AVAILABLE",
    description: "",
};
