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

import { Box, Stack, Typography } from '@wso2/oxygen-ui'
import { useTranslation } from 'react-i18next'
import { Navigate, Outlet } from 'react-router-dom'
import { useSessionQuery } from '../../features/auth/hooks/useAuth'

interface AuthGateProps {
  requireAdmin: boolean
}

function AuthGate({ requireAdmin }: AuthGateProps): React.JSX.Element {
  const { t } = useTranslation('common')
  const sessionQuery = useSessionQuery()

  if (sessionQuery.isLoading) {
    return <Box component="main" sx={{ p: { xs: 2, md: 4 } }} />
  }

  const isLoggedIn = !sessionQuery.isError && Boolean(sessionQuery.data)

  if (isLoggedIn && requireAdmin && !sessionQuery.data?.isAdmin) {
    return <Navigate to="/dashboard" replace />
  }

  if (!isLoggedIn) {
    return (
      <Box component="main" sx={{ p: { xs: 2, md: 4 } }}>
        <Stack spacing={2} alignItems="center" sx={{ mt: { xs: 4, md: 10 } }}>
          <Typography variant="h6" color="text.secondary">
            {t('layout.signedOutMessage', 'Sign in to view this page.')}
          </Typography>
        </Stack>
      </Box>
    )
  }

  return <Outlet />
}

export default AuthGate
