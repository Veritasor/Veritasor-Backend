import DataLoader from 'dataloader';
import * as businessRepository from '../repositories/business.js';
import * as userRepository from '../repositories/userRepository.js';
import { attestationRepository } from '../repositories/attestation.js';

export function createDataLoaders() {
  return {
    userLoader: new DataLoader((ids: readonly string[]) =>
      userRepository.findUsersByIds(ids)
    ),
    businessLoader: new DataLoader((ids: readonly string[]) =>
      businessRepository.listByIds(ids)
    ),
    attestationsByBusinessLoader: new DataLoader(async (businessIds: readonly string[]) =>
      attestationRepository.listByBusinessIds(businessIds)
    ),
  };
}
