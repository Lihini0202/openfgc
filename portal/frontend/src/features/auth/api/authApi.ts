/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import type { LogoutResponse, SessionResponse } from '../../../types/auth'
import { apiRequest } from '../../../utils/apiClient'

/** The BFF's login route is a full-page redirect into the IS login flow, not a fetch call. */
export function loginUrl(): string {
  const baseURL = import.meta.env.VITE_API_BASE_URL
  return `${baseURL}/auth/login`
}

/** IS's own hosted self-registration page - the BFF never handles sign-up directly. */
export function signUpUrl(): string {
  return import.meta.env.VITE_IS_SIGNUP_URL ?? ''
}

export async function fetchSession(): Promise<SessionResponse> {
  return apiRequest<SessionResponse>('/me/session', { method: 'GET' })
}

export async function logout(): Promise<LogoutResponse> {
  return apiRequest<LogoutResponse>('/auth/logout', { method: 'POST' })
}
