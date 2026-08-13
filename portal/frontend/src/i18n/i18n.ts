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

import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import { applyLanguageSideEffects, DEFAULT_LANGUAGE, readStoredLanguage } from './languages'

// Auto-register every language bundle under ./resources/<code>/. Two namespaces
// live there: `common` is our own UI text, and `catalog` is the wording of
// purposes and elements, which administrators create at run time. English is
// the complete set for `common`; other languages fall back to English for any
// key they are missing. Adding a language is as simple as dropping in a new
// resources/<code>/ folder - no change is needed here.
const commonModules = import.meta.glob<{ default: Record<string, unknown> }>(
  './resources/*/common.ts',
  { eager: true },
)
const catalogModules = import.meta.glob<{ default: Record<string, unknown> }>(
  './resources/*/catalog.ts',
  { eager: true },
)

const resources: Record<string, Record<string, Record<string, unknown>>> = {}

function registerNamespace(
  modules: Record<string, { default: Record<string, unknown> }>,
  namespace: string,
): void {
  Object.entries(modules).forEach(([path, module]) => {
    const match = /resources\/([^/]+)\/[^/]+\.ts$/.exec(path)
    if (!match) {
      return
    }
    const language = match[1]
    resources[language] = { ...resources[language], [namespace]: module.default }
  })
}

registerNamespace(commonModules, 'common')
registerNamespace(catalogModules, 'catalog')

const initialLanguage = readStoredLanguage()

i18n.use(initReactI18next).init({
  resources,
  lng: initialLanguage,
  fallbackLng: DEFAULT_LANGUAGE,
  defaultNS: 'common',
  ns: ['common', 'catalog'],
  interpolation: {
    escapeValue: false,
  },
})

applyLanguageSideEffects(initialLanguage)

export default i18n
