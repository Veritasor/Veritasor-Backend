import { z } from 'zod'

export const updateUserProfileSchema = z.object({
  name: z.string().max(100).optional(),
  profile: z.record(z.string(), z.unknown()).optional(),
}).strict()
