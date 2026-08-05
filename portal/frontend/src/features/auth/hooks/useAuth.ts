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

import {
  type UseMutationResult,
  type UseQueryResult,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { fetchSession, logout } from '../api/authApi'
import type { LogoutResponse, SessionResponse } from '../../../types/auth'

export function useSessionQuery(): UseQueryResult<SessionResponse> {
  return useQuery<SessionResponse>({
    queryKey: ['auth', 'session'],
    queryFn: fetchSession,
    retry: false,
  })
}

/**
 * Logs out and returns IS's end-session URL. The caller is responsible for
 * navigating the browser there (a full redirect, not a client-side route) so
 * IS's own session is cleared too, not just our cookies.
 */
export function useLogoutMutation(): UseMutationResult<LogoutResponse, Error, void> {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: logout,
    onSuccess: (): void => {
      queryClient.clear()
    },
  })
}
