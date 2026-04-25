/**
 * Stripe OAuth callback service
 * Handles OAuth callback, validates state, exchanges code for tokens, and
 * idempotently persists the Stripe integration for the user.
 */

import { consumeOAuthState } from './store.js'
import * as IntegrationRepository from '../../../repositories/integration.js'

export interface CallbackParams {
  code: string
  state: string
}

export interface CallbackResult {
  success: boolean
  stripeAccountId?: string
  error?: string
}

const STRIPE_STATE_LENGTH = 64
const STRIPE_STATE_PATTERN = /^[a-f0-9]+$/

/**
 * @notice Validates the Stripe OAuth `state` token shape before store lookup.
 * @dev State must be a 64-char lowercase hex string (32 random bytes encoded in hex).
 *      This rejects malformed input early and avoids reflecting attacker-controlled values.
 */
export function isValidStripeOAuthState(state: string): boolean {
  if (typeof state !== 'string') return false
  if (state.length !== STRIPE_STATE_LENGTH) return false
  return STRIPE_STATE_PATTERN.test(state)
}

/**
 * Handle Stripe OAuth callback
 * Validates state, exchanges authorization code for tokens, and creates integration record
 */
export async function handleCallback(
  params: CallbackParams,
  userId: string
): Promise<CallbackResult> {
  // Validate required parameters
  const code = params.code?.trim()
  const state = params.state?.trim()
  if (!code || !state) {
    return {
      success: false,
      error: 'Missing code, or state'
    }
  }

  // Security guard: reject malformed OAuth state tokens before consuming store entries.
  if (!isValidStripeOAuthState(state)) {
    return {
      success: false,
      error: 'Invalid OAuth state format'
    }
  }

  // Consume and validate state token
  const isValidState = consumeOAuthState(state)
  if (!isValidState) {
    return {
      success: false,
      error: 'Invalid or expired state'
    }
  }
  
  // Exchange authorization code for tokens
  const clientId = process.env.STRIPE_CLIENT_ID
  const clientSecret = process.env.STRIPE_CLIENT_SECRET
  
  const tokenRequestBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: clientId!,
    client_secret: clientSecret!
  })
  
  let response: Response
  try {
    response = await fetch('https://connect.stripe.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: tokenRequestBody.toString()
    })
  } catch (error) {
    return {
      success: false,
      error: 'Failed to reach Stripe API'
    }
  }
  
  // Check if token exchange was successful
  if (!response.ok) {
    return {
      success: false,
      error: 'Token exchange failed'
    }
  }
  
  // Parse token response
  const tokenData = await response.json()
  
  // Validate access token is present
  if (!tokenData.access_token) {
    return {
      success: false,
      error: 'No access token in response'
    }
  }
  
  // Extract token data
  const accessToken = tokenData.access_token
  const refreshToken = tokenData.refresh_token
  const stripeUserId = tokenData.stripe_user_id
  const scope = tokenData.scope
  const tokenType = tokenData.token_type

  if (!stripeUserId || typeof stripeUserId !== 'string') {
    return {
      success: false,
      error: 'No Stripe account ID in response'
    }
  }
  
  const integrationData = {
    userId,
    provider: 'stripe',
    externalId: stripeUserId,
    token: {
      accessToken,
      refreshToken,
      scope,
      tokenType
    },
    metadata: {}
  }

  const existingIntegrations = await IntegrationRepository.listByUserId(userId)
  const existingStripeIntegration = existingIntegrations.find((integration) =>
    integration.provider === 'stripe' && integration.externalId === stripeUserId
  )

  if (existingStripeIntegration) {
    await IntegrationRepository.update(existingStripeIntegration.id, {
      token: integrationData.token,
      metadata: integrationData.metadata
    })
  } else {
    await IntegrationRepository.create(integrationData)
  }
  
  return {
    success: true,
    stripeAccountId: stripeUserId
  }
}
