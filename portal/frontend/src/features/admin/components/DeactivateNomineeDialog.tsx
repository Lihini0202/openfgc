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
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@wso2/oxygen-ui'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

interface DeactivateNomineeDialogProps {
  open: boolean
  ownerId: string
  loading: boolean
  onClose: () => void
  onConfirm: (reason: string) => void
}

const REASONS = ['Admin error', 'Suspected fraud', 'Owner recovered from incapacity'] as const

function DeactivateNomineeDialog({
  open,
  ownerId,
  loading,
  onClose,
  onConfirm,
}: DeactivateNomineeDialogProps): React.JSX.Element {
  const { t } = useTranslation('common')
  const [reason, setReason] = useState<string>('')

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="xs"
      fullWidth
      PaperProps={{
        sx: (theme) => ({
          borderRadius: 1,
          ...theme.applyStyles('light', { bgcolor: theme.palette.grey[50] }),
          ...theme.applyStyles('dark', { bgcolor: 'rgba(255, 255, 255, 0.06)' }),
        }),
      }}
    >
      <DialogTitle sx={{ p: 3, borderBottom: 1, borderColor: 'divider' }}>
        <Stack spacing={0.75}>
          <Typography variant="h6" fontWeight={700}>
            {t('admin.deactivateDialog.title', 'Deactivate Nominee Access')}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('admin.deactivateDialog.subtitle', {
              ownerId,
              defaultValue: "This immediately revokes the nominee's access to {{ownerId}}'s consents.",
            })}
          </Typography>
        </Stack>
      </DialogTitle>

      <DialogContent sx={{ px: 3, pt: 3.5, pb: 3 }}>
        <TextField
          select
          label={t('admin.deactivateDialog.reasonLabel', 'Reason')}
          fullWidth
          value={reason}
          onChange={(event) => {
            setReason(event.target.value)
          }}
          disabled={loading}
        >
          {REASONS.map((option) => (
            <MenuItem key={option} value={option}>
              {option}
            </MenuItem>
          ))}
        </TextField>
      </DialogContent>

      <DialogActions
        sx={{
          p: 3,
          pt: 2,
          borderTop: 1,
          borderColor: 'divider',
          bgcolor: 'background.default',
          flexDirection: 'column',
          gap: 1.25,
        }}
      >
        <Button
          fullWidth
          color="error"
          variant="contained"
          disabled={loading || !reason}
          onClick={() => {
            onConfirm(reason)
          }}
        >
          {loading
            ? t('admin.deactivateDialog.processing', 'Deactivating...')
            : t('admin.deactivateDialog.confirm', 'Deactivate Access')}
        </Button>
        <Button fullWidth variant="outlined" disabled={loading} onClick={onClose}>
          {t('admin.deactivateDialog.cancel', 'Cancel')}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

export default DeactivateNomineeDialog
