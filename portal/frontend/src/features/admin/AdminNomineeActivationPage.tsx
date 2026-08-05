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
  Box,
  Button,
  Card,
  Chip,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  TextField,
  Typography,
} from '@wso2/oxygen-ui'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import HeaderBreadcrumbs from '../../components/layout/main-layout/HeaderBreadcrumbs'
import UserDisplayName from '../nominee/components/UserDisplayName'
import { useUserDisplayQuery } from '../nominee/hooks/useNomineeQueries'
import ActivateNomineeDialog from './components/ActivateNomineeDialog'
import DeactivateNomineeDialog from './components/DeactivateNomineeDialog'
import {
  useActivateNomineeMutation,
  useDeactivateNomineeMutation,
  useNominationByOwnerQuery,
  usePendingNominationsQuery,
  useUserSearchQuery,
} from './hooks/useAdminQueries'

function AdminNomineeActivationPage(): React.JSX.Element {
  const { t } = useTranslation('common')
  const [query, setQuery] = useState<string>('')
  const [selectedOwnerId, setSelectedOwnerId] = useState<string | undefined>(undefined)
  const [activateOpen, setActivateOpen] = useState<boolean>(false)
  const [deactivateOpen, setDeactivateOpen] = useState<boolean>(false)

  const searchQuery = useUserSearchQuery(query)
  const pendingQuery = usePendingNominationsQuery()
  const nominationQuery = useNominationByOwnerQuery(selectedOwnerId)
  const ownerDisplayQuery = useUserDisplayQuery(selectedOwnerId)
  const activateMutation = useActivateNomineeMutation()
  const deactivateMutation = useDeactivateNomineeMutation()

  const controls = nominationQuery.data
  const ownerDisplay = ownerDisplayQuery.data ?? selectedOwnerId ?? ''

  return (
    <Box component="main" sx={{ p: { xs: 2, md: 4 } }}>
      <Stack spacing={3}>
        <Stack spacing={1}>
          <HeaderBreadcrumbs />
          <Typography variant="h4" fontWeight={700}>
            {t('admin.title', 'Nominee Activation')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t(
              'admin.subtitle',
              'Search for an account by name or email to activate or deactivate nominee access after manual legal verification.',
            )}
          </Typography>
        </Stack>

        <Card sx={{ p: 3 }}>
          <Stack spacing={2}>
            <Stack spacing={0.25}>
              <Typography variant="h6" fontWeight={700}>
                {t('admin.pending.title', 'Awaiting Activation')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t(
                  'admin.pending.subtitle',
                  'Nominees who have accepted and are waiting on legal verification.',
                )}
              </Typography>
            </Stack>
            {(pendingQuery.data ?? []).length === 0 && !pendingQuery.isLoading ? (
              <Typography variant="body2" color="text.secondary">
                {t('admin.pending.empty', 'Nothing waiting on activation right now.')}
              </Typography>
            ) : (
              <List sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
                {(pendingQuery.data ?? []).map((nomination) => (
                  <ListItemButton
                    key={nomination.id}
                    selected={nomination.ownerId === selectedOwnerId}
                    onClick={() => {
                      setQuery('')
                      setSelectedOwnerId(nomination.ownerId)
                    }}
                  >
                    <ListItemText
                      primary={<UserDisplayName userId={nomination.ownerId} />}
                      secondary={nomination.nomineeEmail}
                    />
                  </ListItemButton>
                ))}
              </List>
            )}
          </Stack>
        </Card>

        <Card sx={{ p: 3 }}>
          <Stack spacing={2}>
            <TextField
              label={t('admin.search.label', 'Search by name or email')}
              fullWidth
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                setSelectedOwnerId(undefined)
              }}
            />

            {query.trim() && !searchQuery.isLoading ? (
              <List sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
                {(searchQuery.data ?? []).length === 0 ? (
                  <Box sx={{ p: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      {t('admin.search.empty', 'No matching accounts found.')}
                    </Typography>
                  </Box>
                ) : (
                  (searchQuery.data ?? []).map((result) => (
                    <ListItemButton
                      key={result.id}
                      selected={result.id === selectedOwnerId}
                      onClick={() => {
                        setSelectedOwnerId(result.id)
                      }}
                    >
                      <ListItemText primary={result.name} secondary={result.email} />
                    </ListItemButton>
                  ))
                )}
              </List>
            ) : null}
          </Stack>
        </Card>

        {selectedOwnerId && controls ? (
          <Card sx={{ p: 3 }}>
            <Stack spacing={2}>
              <Typography variant="h6" fontWeight={700}>
                {t('admin.controls.title', 'Nominee Controls')}
              </Typography>

              <Stack spacing={0.5}>
                <Typography variant="body2" color="text.secondary">
                  {t('admin.controls.owner', 'Account')}
                </Typography>
                <Typography variant="body1" fontWeight={600}>
                  {ownerDisplay}
                </Typography>
              </Stack>

              <Stack spacing={0.5}>
                <Typography variant="body2" color="text.secondary">
                  {t('admin.controls.nominee', 'Nominated to manage this account')}
                </Typography>
                <Typography variant="body1" fontWeight={600}>
                  {controls.nomineeEmail}
                </Typography>
              </Stack>

              <Stack direction="row" spacing={1.5} alignItems="center">
                <Chip
                  size="small"
                  color={controls.status === 'ACTIVE' ? 'success' : 'default'}
                  variant="outlined"
                  label={
                    controls.status === 'ACTIVE'
                      ? t('nominee.status.active', 'Active')
                      : t('nominee.status.waiting', 'Waiting')
                  }
                />
                {controls.status === 'ACTIVE' ? (
                  <Typography variant="caption" color="text.secondary">
                    {t('admin.controls.activatedMeta', {
                      by: controls.activatedBy,
                      ticket: controls.activationTicket,
                      defaultValue: 'Activated by {{by}} · Ticket: {{ticket}}',
                    })}
                  </Typography>
                ) : null}
              </Stack>

              <Stack direction="row" spacing={1.5}>
                <Button
                  variant="contained"
                  disabled={controls.status !== 'ACCEPTED'}
                  onClick={() => {
                    setActivateOpen(true)
                  }}
                >
                  {t('admin.controls.activate', 'Activate Nominee Access')}
                </Button>
                <Button
                  variant="outlined"
                  color="error"
                  disabled={controls.status !== 'ACTIVE'}
                  onClick={() => {
                    setDeactivateOpen(true)
                  }}
                >
                  {t('admin.controls.deactivate', 'Deactivate')}
                </Button>
              </Stack>
            </Stack>
          </Card>
        ) : null}

        {controls ? (
          <>
            <ActivateNomineeDialog
              key={`activate-${activateOpen}`}
              open={activateOpen}
              ownerId={ownerDisplay}
              nomineeEmail={controls.nomineeEmail}
              loading={activateMutation.isPending}
              errorMessage={activateMutation.error?.message ?? ''}
              onClose={() => {
                setActivateOpen(false)
                activateMutation.reset()
              }}
              onConfirm={(ticket) => {
                activateMutation.mutate(
                  { nominationId: controls.id, ownerId: controls.ownerId, ticket },
                  { onSuccess: () => setActivateOpen(false) },
                )
              }}
            />

            <DeactivateNomineeDialog
              open={deactivateOpen}
              ownerId={ownerDisplay}
              loading={deactivateMutation.isPending}
              onClose={() => {
                setDeactivateOpen(false)
              }}
              onConfirm={(reason) => {
                deactivateMutation.mutate(
                  { nominationId: controls.id, ownerId: controls.ownerId, reason },
                  { onSuccess: () => setDeactivateOpen(false) },
                )
              }}
            />
          </>
        ) : null}
      </Stack>
    </Box>
  )
}

export default AdminNomineeActivationPage
