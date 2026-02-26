import crypto from 'crypto'

export interface Integration {
  id: string;
  userId: string;
  type: 'stripe' | 'razorpay' | 'shopify';
  connectedAt: string;
}

const integrations: Integration[] = [];

export const integrationRepository = {
  findByUserId: (userId: string): Integration[] =>
    integrations.filter((i) => i.userId === userId),

  findByUserIdAndType: (
    userId: string,
    type: Integration['type'],
  ): Integration | null =>
    integrations.find((i) => i.userId === userId && i.type === type) ?? null,

  create: (
    userId: string,
    type: Integration['type'],
  ): Integration => {
    const integration: Integration = {
      id: crypto.randomUUID(),
      userId,
      type,
      connectedAt: new Date().toISOString(),
    };
    integrations.push(integration);
    return integration;
  },
};
