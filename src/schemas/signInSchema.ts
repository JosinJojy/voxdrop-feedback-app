import { z } from "zod";

export const signInSchema = z.object({
  identifier: z.string().min(1,"username or eamil cannot be empty"),
  password: z.string().min(1, "Password should not be empty"),
});
