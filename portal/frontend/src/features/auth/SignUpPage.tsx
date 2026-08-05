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
import { signUpUrl } from './api/authApi'

/**
 * Sign-up redirects to IS's own hosted self-registration page - the BFF never
 * creates users directly. If IS's self-registration flow isn't enabled,
 * VITE_IS_SIGNUP_URL is left blank and this page just shows the message
 * without navigating anywhere.
 */
function SignUpPage(): React.JSX.Element {
  const { t } = useTranslation('common')
  const target = signUpUrl()

  useEffect(() => {
    if (target) {
      window.location.href = target
    }
  }, [target])

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
          {t('auth.signUp.title', 'Sign Up')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {target
            ? t('auth.signUp.redirecting', 'Redirecting to sign up…')
            : t('auth.signUp.unavailable', 'Sign-up is not available yet. Contact an administrator.')}
        </Typography>
      </Stack>
    </Box>
  )
}

export default SignUpPage
