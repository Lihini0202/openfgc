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

import { Box, Button, Stack, Typography } from '@wso2/oxygen-ui'
import { Users } from '@wso2/oxygen-ui-icons-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { findNomineePermission } from '../../../types/nominee'
import { useUserDisplayQuery } from '../hooks/useNomineeQueries'
import { useActingAs } from './actingAsContext'

/**
 * Always-visible reminder that the current tab is operating on someone else's
 * account, with a way out. Rendered above the page content.
 */
function ActingAsBanner(): React.JSX.Element | null {
  const { t } = useTranslation('common')
  const navigate = useNavigate()
  const { session, stopActing } = useActingAs()
  const ownerDisplayQuery = useUserDisplayQuery(session?.ownerId)

  if (!session) {
    return null
  }

  const ownerDisplay = ownerDisplayQuery.data ?? session.ownerId

  const allowed = session.scope
    .map((permission) => {
      const option = findNomineePermission(permission)
      return option ? t(option.labelKey, option.defaultLabel) : permission
    })
    .join(' · ')

  return (
    <Box
      sx={(theme) => ({
        px: { xs: 2, md: 3 },
        py: 1.5,
        borderBottom: 1,
        borderColor: 'divider',
        borderLeft: 3,
        borderLeftColor: 'primary.main',
        ...theme.applyStyles('light', { bgcolor: theme.palette.grey[50] }),
        ...theme.applyStyles('dark', { bgcolor: 'rgba(255, 255, 255, 0.06)' }),
      })}
    >
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={1.5}
        alignItems={{ sm: 'center' }}
        justifyContent="space-between"
      >
        <Stack direction="row" spacing={1.25} alignItems="center">
          <Box sx={{ color: 'text.secondary', display: 'flex', flex: 'none' }}>
            <Users size={17} />
          </Box>
          <Stack spacing={0.25}>
            <Typography variant="body2" fontWeight={700}>
              {t('nominee.acting.banner', 'You are viewing account {{ownerId}} as their nominee', {
                ownerId: ownerDisplay,
              })}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('nominee.acting.allowed', 'You can: {{list}}', { list: allowed })}
            </Typography>
          </Stack>
        </Stack>

        <Button
          size="small"
          variant="outlined"
          sx={{ flex: 'none' }}
          onClick={() => {
            stopActing()
            navigate('/nominations')
          }}
        >
          {t('nominee.acting.exit', 'Exit nominee view')}
        </Button>
      </Stack>
    </Box>
  )
}

export default ActingAsBanner
