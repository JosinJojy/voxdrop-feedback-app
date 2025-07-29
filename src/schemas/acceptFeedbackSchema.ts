import { z } from "zod";

export const acceptFeedbackSchema = z.object({
    isEnabled: z.boolean()
})