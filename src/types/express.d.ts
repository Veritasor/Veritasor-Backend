declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        userId: string;
        email?: string;
        role?: 'user' | 'admin' | 'business_admin';
      };
      business?: {
        id: string;
        userId: string;
        name: string;
        industry: string | null;
        description: string | null;
        website: string | null;
        createdAt: string;
        updatedAt: string;
        suspended?: boolean;
      };
    }
  }
}

export {};
