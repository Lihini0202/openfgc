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

import { Avatar, Box, Button, Card, Chip, Stack, Typography } from '@wso2/oxygen-ui'
import { UserPlus } from '@wso2/oxygen-ui-icons-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import HeaderBreadcrumbs from '../../components/layout/main-layout/HeaderBreadcrumbs'
import { DEFAULT_NOMINEE_PERMISSIONS, findNomineePermission } from '../../types/nominee'
import type { NominationResponse, NominationStatus, NomineePermission } from '../../types/nominee'
import AddNomineeDialog from './components/AddNomineeDialog'
import RemoveNomineeDialog from './components/RemoveNomineeDialog'
import UserDisplayName from './components/UserDisplayName'
import {
  useAcceptNominationMutation,
  useMyNominationsQuery,
  useNominatedForQuery,
  useRemoveNominationMutation,
  useAddNominationMutation,
} from './hooks/useNomineeQueries'

const STATUS_COLOR: Record<NominationStatus, 'success' | 'info' | 'warning' | 'default'> = {
  ACTIVE: 'success',
  ACCEPTED: 'info',
  PENDING: 'warning',
  DEACTIVATED: 'default',
}

function initialsOf(email: string): string {
  return email.slice(0, 2).toUpperCase()
}

function maskNic(nic: string | undefined): string {
  if (!nic) {
    return '—'
  }
  return nic.length <= 4 ? nic : `••••${nic.slice(-4)}`
}

function NominationsPage(): React.JSX.Element {
  const { t } = useTranslation('common')

  const myNominationsQuery = useMyNominationsQuery()
  const nominatedForQuery = useNominatedForQuery()
  const addNominationMutation = useAddNominationMutation()
  const acceptNominationMutation = useAcceptNominationMutation()
  const removeNominationMutation = useRemoveNominationMutation()

  const [dialogOpen, setDialogOpen] = useState<boolean>(false)
  // Which nomination the remove dialog is for. An owner may have many, so the
  // dialog has to be told which one rather than assuming "the" nominee.
  const [removalTarget, setRemovalTarget] = useState<NominationResponse | null>(null)

  const myNominations = myNominationsQuery.data ?? []

  const statusLabel = (status: NominationStatus): string =>
    ({
      ACTIVE: t('nominee.mine.status.active', 'Active'),
      ACCEPTED: t('nominee.mine.status.accepted', 'Accepted'),
      PENDING: t('nominee.mine.status.pending', 'Awaiting acceptance'),
      DEACTIVATED: t('nominee.mine.status.deactivated', 'Deactivated'),
    })[status]

  const permissionLabel = (permission: string): string => {
    const option = findNomineePermission(permission)
    return option ? t(option.labelKey, option.defaultLabel) : permission
  }

  return (
    <Box component="main" sx={{ p: { xs: 2, md: 4 } }}>
      <Stack spacing={3}>
        <Stack spacing={1}>
          <HeaderBreadcrumbs />
          <Typography variant="h4" fontWeight={700}>
            {t('nominee.title', 'Nominations')}
          </Typography>
        </Stack>

        {myNominationsQuery.isError || nominatedForQuery.isError ? (
          <Typography color="error.main">
            {t('nominee.messages.loadFailed', 'Unable to load nominations right now.')}
          </Typography>
        ) : null}

        <Card sx={{ p: 3 }}>
          <Stack spacing={2.5}>
            <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
              <Stack spacing={0.25}>
                <Typography variant="h6" fontWeight={700}>
                  {t('nominee.mine.title', 'My Nominees')}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'nominee.mine.subtitle',
                    'The people you authorise to act for you. You choose what each of them may do.',
                  )}
                </Typography>
              </Stack>
              <Stack direction="row" spacing={1}>
                <Button
                  variant="contained"
                  startIcon={<UserPlus size={16} />}
                  onClick={() => {
                    setDialogOpen(true)
                  }}
                >
                  {t('nominee.mine.add', 'Add Nominee')}
                </Button>
              </Stack>
            </Stack>

            {myNominations.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('nominee.mine.empty', "You haven't nominated anyone yet.")}
              </Typography>
            ) : (
              <Stack
                spacing={1.5}
                divider={<Box sx={{ borderBottom: 1, borderColor: 'divider' }} />}
              >
                {myNominations.map((nomination: NominationResponse) => (
                  <Stack
                    key={nomination.id}
                    direction="row"
                    spacing={1.5}
                    alignItems="flex-start"
                    justifyContent="space-between"
                  >
                    <Stack direction="row" spacing={1.5} alignItems="center" sx={{ minWidth: 0 }}>
                      <Avatar
                        sx={{
                          width: 40,
                          height: 40,
                          fontSize: 14,
                          fontWeight: 700,
                          bgcolor: 'primary.main',
                        }}
                      >
                        {initialsOf(nomination.nomineeEmail)}
                      </Avatar>
                      <Stack spacing={0.5} sx={{ minWidth: 0 }}>
                        <Stack
                          direction="row"
                          spacing={1}
                          alignItems="center"
                          flexWrap="wrap"
                          useFlexGap
                        >
                          <Typography variant="body1" fontWeight={600}>
                            {nomination.nomineeEmail}
                          </Typography>
                          <Chip
                            size="small"
                            color={STATUS_COLOR[nomination.status]}
                            variant="outlined"
                            label={statusLabel(nomination.status)}
                          />
                        </Stack>
                        <Typography variant="body2" color="text.secondary">
                          {'NIC '}
                          {maskNic(nomination.nomineeNic)}
                        </Typography>
                        <Stack
                          direction="row"
                          spacing={0.5}
                          flexWrap="wrap"
                          useFlexGap
                          sx={{ pt: 0.25 }}
                        >
                          {nomination.permissions.map((permission: NomineePermission) => (
                            <Chip
                              key={permission}
                              size="small"
                              variant="outlined"
                              label={permissionLabel(permission)}
                              color={permission === 'ACCOUNT_DELETE' ? 'error' : 'default'}
                            />
                          ))}
                        </Stack>
                      </Stack>
                    </Stack>
                    <Button
                      variant="outlined"
                      color="error"
                      size="small"
                      onClick={() => {
                        setRemovalTarget(nomination)
                      }}
                    >
                      {t('nominee.mine.remove', 'Remove')}
                    </Button>
                  </Stack>
                ))}
              </Stack>
            )}
          </Stack>
        </Card>

        <Card sx={{ p: 3 }}>
          <Stack spacing={2}>
            <Typography variant="h6" fontWeight={700}>
              {t('nominee.nominatedFor.title', 'Assigned Accounts')}
            </Typography>

            {(nominatedForQuery.data ?? []).length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t(
                  'nominee.nominatedFor.empty',
                  'No accounts have been assigned to you to manage.',
                )}
              </Typography>
            ) : (
              <Stack
                spacing={1.5}
                divider={<Box sx={{ borderBottom: 1, borderColor: 'divider' }} />}
              >
                {(nominatedForQuery.data ?? []).map((entry: NominationResponse) => (
                  <Stack
                    key={entry.id}
                    direction={{ xs: 'column', sm: 'row' }}
                    spacing={1.5}
                    alignItems={{ sm: 'center' }}
                    justifyContent="space-between"
                    sx={{ pb: 1.5 }}
                  >
                    <Stack spacing={0.25}>
                      <Typography variant="body1" fontWeight={600}>
                        <UserDisplayName userId={entry.ownerId} />
                      </Typography>
                    </Stack>

                    <Stack direction="row" spacing={1.5} alignItems="center">
                      <Chip
                        size="small"
                        color={STATUS_COLOR[entry.status]}
                        variant="outlined"
                        label={statusLabel(entry.status)}
                      />
                      {entry.status === 'PENDING' ? (
                        <Button
                          size="small"
                          variant="outlined"
                          disabled={acceptNominationMutation.isPending}
                          onClick={() => {
                            acceptNominationMutation.mutate(entry.id)
                          }}
                        >
                          {t('nominee.nominatedFor.accept', 'Accept')}
                        </Button>
                      ) : null}
                      {entry.status === 'ACTIVE' ? (
                        <Button
                          size="small"
                          variant="contained"
                          onClick={() => {
                            window.open(`/acting/${entry.ownerId}`, '_blank', 'noopener')
                          }}
                        >
                          {t('nominee.nominatedFor.openAccount', 'Open account →')}
                        </Button>
                      ) : null}
                    </Stack>
                  </Stack>
                ))}
              </Stack>
            )}
          </Stack>
        </Card>

        <AddNomineeDialog
          key={`nominee-dialog-${String(dialogOpen)}`}
          open={dialogOpen}
          loading={addNominationMutation.isPending}
          errorMessage={addNominationMutation.error?.message ?? ''}
          mode="add"
          initialEmail=""
          initialNic=""
          initialPermissions={DEFAULT_NOMINEE_PERMISSIONS}
          onClose={() => {
            setDialogOpen(false)
          }}
          onConfirm={(submission) => {
            addNominationMutation.mutate(submission, {
              onSuccess: () => {
                setDialogOpen(false)
              },
            })
          }}
        />

        {removalTarget ? (
          <RemoveNomineeDialog
            key={`remove-nominee-dialog-${removalTarget.id}`}
            open
            nomineeEmail={removalTarget.nomineeEmail}
            loading={removeNominationMutation.isPending}
            onClose={() => {
              setRemovalTarget(null)
            }}
            onConfirm={() => {
              removeNominationMutation.mutate(removalTarget.id, {
                onSuccess: () => {
                  setRemovalTarget(null)
                },
              })
            }}
          />
        ) : null}
      </Stack>
    </Box>
  )
}

export default NominationsPage
