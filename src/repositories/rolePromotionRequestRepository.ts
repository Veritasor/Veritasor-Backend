import { randomBytes } from 'crypto'
import { config } from '../config/index.js'

export type Role = 'user' | 'admin' | 'business_admin'
export type RolePromotionRequestStatus = 'pending' | 'approved' | 'expired' | 'rejected'

export interface RolePromotionRequest {
  id: string
  targetUserId: string
  requestedRole: Role
  requestedByAdminId: string
  status: RolePromotionRequestStatus
  createdAt: Date
  expiresAt: Date
  approvedByAdminId?: string
  approvedAt?: Date
}

const rolePromotionRequests: Map<string, RolePromotionRequest> = new Map()
const targetUserIndex: Map<string, string[]> = new Map() // targetUserId -> requestIds

function cloneDate(date: Date): Date {
  return new Date(date.getTime())
}

function cloneRequest(request: RolePromotionRequest): RolePromotionRequest {
  return {
    ...request,
    createdAt: cloneDate(request.createdAt),
    expiresAt: cloneDate(request.expiresAt),
    ...(request.approvedAt ? { approvedAt: cloneDate(request.approvedAt) } : {}),
  }
}

function saveRequest(request: RolePromotionRequest): RolePromotionRequest {
  const sanitized = cloneRequest(request)
  rolePromotionRequests.set(sanitized.id, sanitized)

  if (!targetUserIndex.has(sanitized.targetUserId)) {
    targetUserIndex.set(sanitized.targetUserId, [])
  }
  const targetUserRequests = targetUserIndex.get(sanitized.targetUserId)!
  if (!targetUserRequests.includes(sanitized.id)) {
    targetUserRequests.push(sanitized.id)
  }

  return sanitized
}

function generateId(): string {
  return randomBytes(16).toString('hex')
}

export async function createRolePromotionRequest(
  targetUserId: string,
  requestedRole: Role,
  requestedByAdminId: string
): Promise<RolePromotionRequest> {
  const now = new Date()
  const expiresAt = new Date(now.getTime() + config.rolePromotion.ttlMinutes * 60 * 1000)

  const request: RolePromotionRequest = {
    id: generateId(),
    targetUserId,
    requestedRole,
    requestedByAdminId,
    status: 'pending',
    createdAt: now,
    expiresAt,
  }

  const stored = saveRequest(request)
  return cloneRequest(stored)
}

export async function findRolePromotionRequestById(
  id: string
): Promise<RolePromotionRequest | null> {
  const request = rolePromotionRequests.get(id)
  return request ? cloneRequest(request) : null
}

export async function updateRolePromotionRequest(
  id: string,
  updates: Partial<Pick<RolePromotionRequest, 'status' | 'approvedByAdminId' | 'approvedAt'>>
): Promise<RolePromotionRequest | null> {
  const current = rolePromotionRequests.get(id)
  if (!current) return null

  const next: RolePromotionRequest = {
    ...current,
    status: updates.status ?? current.status,
    approvedByAdminId: updates.approvedByAdminId ?? current.approvedByAdminId,
    approvedAt: updates.approvedAt ?? current.approvedAt,
  }

  const stored = saveRequest(next)
  return cloneRequest(stored)
}

export async function findPendingRolePromotionRequestsForTarget(
  targetUserId: string
): Promise<RolePromotionRequest[]> {
  const requestIds = targetUserIndex.get(targetUserId) || []
  const requests = requestIds
    .map(id => rolePromotionRequests.get(id))
    .filter((req): req is RolePromotionRequest => req !== undefined && req.status === 'pending')
  return requests.map(cloneRequest)
}

export async function sweepExpiredRequests(): Promise<number> {
  const now = new Date()
  let count = 0

  for (const [id, request] of rolePromotionRequests.entries()) {
    if (request.status === 'pending' && request.expiresAt < now) {
      await updateRolePromotionRequest(id, { status: 'expired' })
      count++
    }
  }

  return count
}

export function clearAllRolePromotionRequests(): void {
  rolePromotionRequests.clear()
  targetUserIndex.clear()
}
