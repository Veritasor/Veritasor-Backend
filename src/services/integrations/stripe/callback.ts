/**
 * Stripe OAuth callback service
 * Handles OAuth callback, validates state, exchanges code for tokens, and creates integration
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

/**
 * Handle Stripe OAuth callback
 * Validates state, exchanges authorization code for tokens, and creates integration record
 */
export async function handleCallback(
  params: CallbackParams,
  userId: string
): Promise<CallbackResult> {
  // Validate required parameters
  if (!params.code || !params.state) {
    return {
      success: false,
      error: 'Missing code, or state'
    }
  }
  
  // Consume and validate state token
  const isValidState = consumeOAuthState(params.state)
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
    code: params.code,
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
  
  // Create integration record
  await IntegrationRepository.create({
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
  })
  
  return {
    success: true,
    stripeAccountId: stripeUserId
  }
}
