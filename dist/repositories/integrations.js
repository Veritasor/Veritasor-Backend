import crypto from 'crypto';
const store = [];
export const integrationRepository = {
    create: (data) => {
        const rec = {
            ...data,
            id: crypto.randomUUID(),
            createdAt: new Date().toISOString(),
        };
        store.push(rec);
        return rec;
    },
    findById: (id) => store.find((s) => s.id === id) ?? null,
    findByUserAndProvider: (userId, provider) => store.find((s) => s.userId === userId && s.provider === provider) ?? null,
    listByUser: (userId) => store.filter((s) => s.userId === userId),
    deleteById: (id) => {
        const idx = store.findIndex((s) => s.id === id);
        if (idx === -1)
            return false;
        store.splice(idx, 1);
        return true;
    },
};
export default integrationRepository;
