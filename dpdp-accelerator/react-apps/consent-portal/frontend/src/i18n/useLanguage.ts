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

import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  DEFAULT_LANGUAGE_META,
  getLanguageMeta,
  LANGUAGES,
  storeLanguage,
  type LanguageMeta,
} from './languages'

export interface UseLanguageResult {
  /** The language currently rendered, always a member of LANGUAGES. */
  current: LanguageMeta
  /** Every language the user may choose, in Eighth Schedule order. */
  languages: LanguageMeta[]
  /** Switch language: re-renders the tree, and persists the choice. */
  setLanguage: (code: string) => void
}

/**
 * Single entry point for reading and changing the portal language.
 *
 * Document-level effects (the lang attribute) are applied by
 * LocaleProvider, which reacts to the i18next language rather than to this
 * call, so a language changed from anywhere stays consistent.
 */
export default function useLanguage(): UseLanguageResult {
  const { i18n } = useTranslation('common')

  const setLanguage = useCallback(
    (code: string) => {
      if (!getLanguageMeta(code)) return
      // changeLanguage resolves once the bundle is active; resources are
      // bundled eagerly, so there is nothing to await and nothing to catch.
      i18n.changeLanguage(code).catch(() => {})
      storeLanguage(code)
    },
    [i18n],
  )

  const current = getLanguageMeta(i18n.resolvedLanguage ?? i18n.language) ?? DEFAULT_LANGUAGE_META

  return { current, languages: LANGUAGES, setLanguage }
}
