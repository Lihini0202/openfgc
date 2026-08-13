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

/**
 * Languages offered by the portal.
 *
 * Section 5(3) of the Digital Personal Data Protection Act, 2023 requires that
 * the Data Principal be given the option to access the notice - and, by
 * extension, the rights-exercise flows it points to - in English or any of the
 * 22 languages listed in the Eighth Schedule to the Constitution of India.
 * The list below is English + those 22 scheduled languages.
 */

export interface LanguageMeta {
  /** BCP-47 / ISO code used as the i18next language key and resource folder name. */
  code: string
  /** Native-script name shown in the switcher. */
  endonym: string
  /** English name (for tooltips / accessibility). */
  english: string
}

export const LANGUAGES: LanguageMeta[] = [
  { code: 'en', endonym: 'English', english: 'English' },
  { code: 'hi', endonym: 'हिन्दी', english: 'Hindi' },
  { code: 'as', endonym: 'অসমীয়া', english: 'Assamese' },
  { code: 'bn', endonym: 'বাংলা', english: 'Bengali' },
  { code: 'brx', endonym: 'बड़ो', english: 'Bodo' },
  { code: 'doi', endonym: 'डोगरी', english: 'Dogri' },
  { code: 'gu', endonym: 'ગુજરાતી', english: 'Gujarati' },
  { code: 'kn', endonym: 'ಕನ್ನಡ', english: 'Kannada' },
  { code: 'ks', endonym: 'کٲشُر', english: 'Kashmiri' },
  { code: 'kok', endonym: 'कोंकणी', english: 'Konkani' },
  { code: 'mai', endonym: 'मैथिली', english: 'Maithili' },
  { code: 'ml', endonym: 'മലയാളം', english: 'Malayalam' },
  { code: 'mni', endonym: 'মৈতৈলোন্', english: 'Manipuri (Meitei)' },
  { code: 'mr', endonym: 'मराठी', english: 'Marathi' },
  { code: 'ne', endonym: 'नेपाली', english: 'Nepali' },
  { code: 'or', endonym: 'ଓଡ଼ିଆ', english: 'Odia' },
  { code: 'pa', endonym: 'ਪੰਜਾਬੀ', english: 'Punjabi' },
  { code: 'sa', endonym: 'संस्कृतम्', english: 'Sanskrit' },
  { code: 'sat', endonym: 'ᱥᱟᱱᱛᱟᱲᱤ', english: 'Santali' },
  { code: 'sd', endonym: 'سنڌي', english: 'Sindhi' },
  { code: 'ta', endonym: 'தமிழ்', english: 'Tamil' },
  { code: 'te', endonym: 'తెలుగు', english: 'Telugu' },
  { code: 'ur', endonym: 'اردو', english: 'Urdu' },
]

export const DEFAULT_LANGUAGE = 'en'

/** English, the first entry above and the fallback for every other language. */
export const DEFAULT_LANGUAGE_META: LanguageMeta = LANGUAGES[0]

/** localStorage key used to remember the language choice. */
export const LANGUAGE_STORAGE_KEY = 'dpdp.lang'

const LANGUAGE_BY_CODE = new Map(LANGUAGES.map((lang) => [lang.code, lang]))

export function getLanguageMeta(code: string): LanguageMeta | undefined {
  return LANGUAGE_BY_CODE.get(code)
}

/**
 * Apply document-level side effects for a language: set the lang attribute, so
 * assistive technology and the browser's own text handling know which language
 * the page is in. Safe to call in any environment (guards against a missing
 * document, e.g. during SSR/tests).
 *
 * The portal renders left-to-right in every language, including those written
 * in Perso-Arabic script, so no direction is applied here.
 */
export function applyLanguageSideEffects(code: string): void {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('lang', code)
}

/** Read the persisted language, falling back to the default. */
export function readStoredLanguage(): string {
  try {
    const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY)
    if (stored && LANGUAGE_BY_CODE.has(stored)) return stored
  } catch {
    // localStorage unavailable - fall through to default
  }
  return DEFAULT_LANGUAGE
}

/** Persist the language choice; ignored where localStorage is unavailable. */
export function storeLanguage(code: string): void {
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, code)
  } catch {
    // ignore
  }
}
