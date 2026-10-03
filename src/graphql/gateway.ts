import { stitchSchemas } from '@graphql-tools/stitch';
import { userSchema } from './subgraphs/user.js';
import { businessSchema } from './subgraphs/business.js';
import { attestationSchema } from './subgraphs/attestation.js';

export const gatewaySchema = stitchSchemas({
  subschemas: [
    { schema: userSchema },
    { schema: businessSchema },
    { schema: attestationSchema },
  ],
  typeDefs: `
    extend type Business {
      user: User
      attestations: [Attestation!]
    }
  `,
  resolvers: {
    Business: {
      user: {
        selectionSet: `{ userId }`,
        resolve(business, _args, context: any) {
          return context.loaders.userLoader.load(business.userId);
        },
      },
      attestations: {
        selectionSet: `{ id }`,
        resolve(business, _args, context: any) {
          return context.loaders.attestationsByBusinessLoader.load(business.id);
        },
      },
    },
  },
});
