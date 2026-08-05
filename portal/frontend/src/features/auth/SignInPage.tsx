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
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { loginUrl } from './api/authApi'

/**
 * Sign-in is a full-page redirect into IS's own login page, not a form we
 * render ourselves - IS owns the credential UI, MFA, etc. This page is just
 * the brief transition shown while that redirect happens.
 */
function SignInPage(): React.JSX.Element {
  const { t } = useTranslation('common')

  useEffect(() => {
    window.location.href = loginUrl()
  }, [])

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2,
      }}
    >
      <Stack spacing={1} alignItems="center">
        <Typography variant="h6" fontWeight={700}>
          {t('auth.signIn.title', 'Sign In')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('auth.signIn.redirecting', 'Redirecting to sign in…')}
        </Typography>
      </Stack>
    </Box>
  )
}

export default SignInPage
