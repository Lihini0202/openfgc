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

import { Navigate, Route, Routes } from 'react-router-dom'
import AuthGate from './components/auth/AuthGate'
import AdminSidebar from './components/layout/sidebar/AdminSidebar'
import AppSidebar from './components/layout/sidebar/AppSidebar'
import MainLayout from './components/layout/main-layout/MainLayout'
import AdminNomineeActivationPage from './features/admin/AdminNomineeActivationPage'
import SignInPage from './features/auth/SignInPage'
import SignUpPage from './features/auth/SignUpPage'
import ConsentDetailsPage from './features/consent-registry/ConsentDetailsPage'
import ConsentRegistryPage from './features/consent-registry/ConsentRegistryPage'
import DashboardPage from './features/dashboard/DashboardPage'
import ActingAsGuard from './features/nominee/actingAs/ActingAsGuard'
import ActingCallbackPage from './features/nominee/actingAs/ActingCallbackPage'
import StartActingPage from './features/nominee/actingAs/StartActingPage'
import NomineeConsentDetailsPage from './features/nominee/NomineeConsentDetailsPage'
import NomineeManagePage from './features/nominee/NomineeManagePage'
import NominationsPage from './features/nominee/NominationsPage'

function App(): React.JSX.Element {
  return (
    <Routes>
      <Route path="/login" element={<SignInPage />} />
      <Route path="/signup" element={<SignUpPage />} />

      <Route element={<MainLayout sidebar={AppSidebar} />}>
        <Route element={<AuthGate requireAdmin={false} />}>
          {/* The callback must be matched before /acting/:ownerId, which would
              otherwise swallow it as an owner id. */}
          <Route path="/acting/callback" element={<ActingCallbackPage />} />
          <Route path="/acting/:ownerId" element={<StartActingPage />} />

          <Route element={<ActingAsGuard />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/consents" element={<ConsentRegistryPage />} />
            <Route path="/consents/:id" element={<ConsentDetailsPage />} />
            <Route path="/nominations" element={<NominationsPage />} />
            <Route path="/nominee/manage/:ownerId" element={<NomineeManagePage />} />
            <Route
              path="/nominee/manage/:ownerId/consents/:consentId"
              element={<NomineeConsentDetailsPage />}
            />
            <Route path="*" element={<Navigate to="/consents" replace />} />
          </Route>
        </Route>
      </Route>

      <Route element={<MainLayout sidebar={AdminSidebar} />}>
        <Route element={<AuthGate requireAdmin />}>
          <Route path="/admin/nominees" element={<AdminNomineeActivationPage />} />
        </Route>
      </Route>
    </Routes>
  )
}

export default App
