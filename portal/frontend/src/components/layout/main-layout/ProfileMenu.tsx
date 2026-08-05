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

import { Divider, IconButton, ListItemIcon, ListItemText, Menu, MenuItem } from '@wso2/oxygen-ui'
import {
  CircleUserRound,
  LogIn,
  LogOut,
  Settings,
  UserPen,
  UserPlus,
} from '@wso2/oxygen-ui-icons-react'
import { type MouseEvent, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { useLogoutMutation, useSessionQuery } from '../../../features/auth/hooks/useAuth'

function ProfileMenu(): React.JSX.Element {
  const { t } = useTranslation('common')
  const navigate = useNavigate()
  const sessionQuery = useSessionQuery()
  const logoutMutation = useLogoutMutation()
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null)

  const isLoggedIn = Boolean(sessionQuery.data)
  const open = Boolean(anchorEl)

  const closeMenu = (): void => {
    setAnchorEl(null)
  }

  return (
    <>
      <IconButton
        size="medium"
        aria-label={t('layout.userAvatarAriaLabel')}
        onClick={(event: MouseEvent<HTMLElement>) => {
          setAnchorEl(event.currentTarget)
        }}
      >
        <CircleUserRound size={26} />
      </IconButton>

      <Menu anchorEl={anchorEl} open={open} onClose={closeMenu}>
        {isLoggedIn
          ? [
              <MenuItem key="edit-profile" disabled>
                <ListItemIcon>
                  <UserPen size={18} />
                </ListItemIcon>
                <ListItemText>{t('layout.profileMenu.editProfile', 'Edit Profile')}</ListItemText>
              </MenuItem>,
              <MenuItem key="settings" disabled>
                <ListItemIcon>
                  <Settings size={18} />
                </ListItemIcon>
                <ListItemText>{t('layout.profileMenu.settings', 'Settings')}</ListItemText>
              </MenuItem>,
              <Divider key="divider" />,
              <MenuItem
                key="logout"
                onClick={() => {
                  closeMenu()
                  logoutMutation.mutate(undefined, {
                    onSuccess: ({ logoutUrl }) => {
                      window.location.href = logoutUrl
                    },
                  })
                }}
              >
                <ListItemIcon>
                  <LogOut size={18} />
                </ListItemIcon>
                <ListItemText>{t('layout.profileMenu.logout', 'Logout')}</ListItemText>
              </MenuItem>,
            ]
          : [
              <MenuItem
                key="login"
                onClick={() => {
                  closeMenu()
                  navigate('/login')
                }}
              >
                <ListItemIcon>
                  <LogIn size={18} />
                </ListItemIcon>
                <ListItemText>{t('layout.profileMenu.login', 'Login')}</ListItemText>
              </MenuItem>,
              <MenuItem
                key="signup"
                onClick={() => {
                  closeMenu()
                  navigate('/signup')
                }}
              >
                <ListItemIcon>
                  <UserPlus size={18} />
                </ListItemIcon>
                <ListItemText>{t('layout.profileMenu.signUp', 'Sign Up')}</ListItemText>
              </MenuItem>,
            ]}
      </Menu>
    </>
  )
}

export default ProfileMenu
