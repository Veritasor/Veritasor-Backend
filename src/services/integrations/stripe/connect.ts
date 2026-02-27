/**
 * Stripe OAuth connect service
 * Initiates OAuth flow by generating state token and constructing authorization URL
 */

import crypto from 'crypto'
import { setOAuthState } from './store.js'

export interface ConnectResult {
  redirectUrl: string
  state: string
}

/**
 * Start Stripe OAuth connect flow
 * Generates state token, stores it with expiration, and constructs authorization URL
 */
export function startConnect(): ConnectResult {
  // Generate cryptographically secure 32-byte state token
  const state = crypto.randomBytes(32).toString('hex')
  
  // Store state token with 10-minute expiration
  const expiresAt = Date.now() + 10 * 60 * 1000
  setOAuthState(state, expiresAt)
  
  // Read configuration from environment variables
  const clientId = process.env.STRIPE_CLIENT_ID
  const redirectUri = process.env.STRIPE_REDIRECT_URI
  const scopes = process.env.STRIPE_SCOPES || 'read_write'
  
  // Construct Stripe authorization URL
  const params = new URLSearchParams({
    client_id: clientId!,
    redirect_uri: redirectUri!,
    state,
    scope: scopes,
    response_type: 'code'
  })
  
  const redirectUrl = `https://connect.stripe.com/oauth/authorize?${params.toString()}`
  
  return {
    redirectUrl,
    state
  }
}
