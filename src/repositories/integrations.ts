import crypto from 'crypto'

export type ConnectedIntegration = {
  id: string
  provider: string
  userId: string
  businessId: string
  meta: Record<string, any>
  createdAt: string
}

const store: ConnectedIntegration[] = []

export const integrationRepository = {
  create: (data: Omit<ConnectedIntegration, 'id' | 'createdAt'>): ConnectedIntegration => {
    const rec: ConnectedIntegration = {
      ...data,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    }
    store.push(rec)
    return rec
  },

  findById: (id: string) => store.find((s) => s.id === id) ?? null,

  findByUserAndProvider: (userId: string, provider: string) =>
    store.find((s) => s.userId === userId && s.provider === provider) ?? null,

  findByBusinessAndProvider: (businessId: string, provider: string) =>
    store.find((s) => s.businessId === businessId && s.provider === provider) ?? null,

  listByUser: (userId: string) => store.filter((s) => s.userId === userId),

  listByBusiness: (businessId: string) => store.filter((s) => s.businessId === businessId),

  deleteById: (id: string) => {
    const idx = store.findIndex((s) => s.id === id)
    if (idx === -1) return false
    store.splice(idx, 1)
    return true
  },
}

export default integrationRepository
