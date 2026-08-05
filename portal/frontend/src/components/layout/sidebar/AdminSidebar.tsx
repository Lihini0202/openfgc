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

import { Sidebar } from '@wso2/oxygen-ui'
import { UserCog } from '@wso2/oxygen-ui-icons-react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

interface AdminSidebarProps {
  collapsed: boolean
}

const ADMIN_ITEM_ID = 'nominee-activation'

function AdminSidebar({ collapsed }: AdminSidebarProps): React.JSX.Element {
  const { t } = useTranslation('common')
  const navigate = useNavigate()

  return (
    <Sidebar
      collapsed={collapsed}
      activeItem={ADMIN_ITEM_ID}
      onSelect={(id) => {
        if (id === ADMIN_ITEM_ID) {
          navigate('/admin/nominees')
        }
      }}
      aria-label={t('sidebar.adminAriaLabel')}
    >
      <Sidebar.Nav>
        <Sidebar.Category>
          <Sidebar.CategoryLabel>{t('sidebar.admin')}</Sidebar.CategoryLabel>
          <Sidebar.Item id={ADMIN_ITEM_ID}>
            <Sidebar.ItemIcon>
              <UserCog size={18} />
            </Sidebar.ItemIcon>
            <Sidebar.ItemLabel>{t('sidebar.nomineeActivation')}</Sidebar.ItemLabel>
          </Sidebar.Item>
        </Sidebar.Category>
      </Sidebar.Nav>
    </Sidebar>
  )
}

export default AdminSidebar
