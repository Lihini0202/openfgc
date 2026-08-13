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
 * Wording for purposes and elements, which administrators create at run time
 * and which therefore cannot live in common.ts.
 *
 * Keys are the item's `name` exactly as entered. An optional `name@version`
 * key overrides one specific version. Add missing keys with
 * `pnpm i18n:catalog`, then fill in the text - anything left blank falls back
 * to the English the server returns.
 */
const catalogSat = {
  purposes: {},
  elements: {},
} as const

export default catalogSat
