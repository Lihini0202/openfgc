/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

/**
 * Refreshes the per-language `catalog.ts` files from the live catalog.
 *
 * Purposes and elements are created by administrators at run time, so the list
 * of things needing translation is only knowable from the server. This script
 * reads that list and writes:
 *
 *   - resources/en/catalog.ts  - the work list, with the exact English wording
 *   - resources/<lang>/catalog.ts - the same keys with blank values to fill in
 *
 * Existing translations are never overwritten and never removed. Keys that have
 * disappeared from the server are kept too: consents granted earlier still
 * reference them.
 *
 * Usage:
 *   CATALOG_API_BASE=https://portal.example CATALOG_API_TOKEN=... pnpm i18n:catalog
 *   pnpm i18n:catalog --input catalog-dump.json
 *   pnpm i18n:catalog --check      (report only, write nothing)
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const RESOURCES = 'src/i18n/resources'
const PAGE_SIZE = 100

const args = process.argv.slice(2)
const checkOnly = args.includes('--check')
const inputIndex = args.indexOf('--input')
const inputFile = inputIndex === -1 ? undefined : args[inputIndex + 1]

const LICENSE = `/*
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
`

const EN_DOC = `/**
 * The English work list for catalog translations - regenerate with
 * \`pnpm i18n:catalog\`.
 *
 * Nothing reads this at run time. The server already returns English in
 * displayName and description, and an untranslated item falls back to it. This
 * file exists so translators have an accurate list of every key and its exact
 * English wording to translate from.
 */`

const OTHER_DOC = `/**
 * Wording for purposes and elements, which administrators create at run time
 * and which therefore cannot live in common.ts.
 *
 * Keys are the item's \`name\` exactly as entered. An optional \`name@version\`
 * key overrides one specific version. Add missing keys with
 * \`pnpm i18n:catalog\`, then fill in the text - anything left blank falls back
 * to the English the server returns.
 */`

function pascal(code) {
  return code
    .split(/[-_]/)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join('')
}

/**
 * A TS string literal in the repository's style: single quotes, except where
 * the text itself contains more single quotes than double ones - which is the
 * rule Prettier applies, so the output needs no reformatting.
 */
function quote(value) {
  const escaped = value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')
  const singles = (escaped.match(/'/g) ?? []).length
  const doubles = (escaped.match(/"/g) ?? []).length

  return singles > doubles
    ? `"${escaped.replace(/"/g, '\\"')}"`
    : `'${escaped.replace(/'/g, "\\'")}'`
}

/**
 * Object keys are the administrator-entered name, which may be anything at all.
 * Prettier's default quoteProps drops the quotes where the key is a valid
 * identifier, so emit it that way and the output needs no reformatting.
 */
function keyLiteral(key) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) ? key : quote(key)
}

async function fetchAll(base, token, path) {
  const collected = []
  let offset = 0

  // Sequential by nature: each request's offset depends on how much the
  // previous one returned, so the pages cannot be fetched in parallel.
  /* eslint-disable no-await-in-loop */
  for (;;) {
    const url = `${base.replace(/\/$/, '')}${path}?limit=${String(PAGE_SIZE)}&offset=${String(offset)}`
    const response = await fetch(url, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })

    if (!response.ok) {
      throw new Error(`GET ${url} failed: ${String(response.status)} ${response.statusText}`)
    }

    const payload = await response.json()
    const page = payload.data ?? []
    collected.push(...page)

    const total = payload.metadata?.total ?? collected.length
    offset += PAGE_SIZE

    if (page.length === 0 || collected.length >= total) {
      return collected
    }
  }
  /* eslint-enable no-await-in-loop */
}

async function loadCatalog() {
  if (inputFile) {
    const dump = JSON.parse(readFileSync(inputFile, 'utf8'))
    return { purposes: dump.purposes ?? [], elements: dump.elements ?? [] }
  }

  const base = process.env.CATALOG_API_BASE
  const token = process.env.CATALOG_API_TOKEN

  if (!base) {
    throw new Error(
      'Set CATALOG_API_BASE (and CATALOG_API_TOKEN if the portal requires one), or pass --input <file.json>',
    )
  }

  const [purposes, elements] = await Promise.all([
    fetchAll(base, token, '/api/consent-purposes'),
    fetchAll(base, token, '/api/consent-elements'),
  ])

  return { purposes, elements }
}

/**
 * Reads the object literal back out of an existing catalog.ts.
 *
 * These files are hand-edited by translators, so they are real TypeScript
 * rather than strict JSON - single quotes, trailing commas and so on. Rather
 * than hand-roll a parser, the literal is evaluated. This only ever runs
 * locally against files in this repository.
 */
function readExisting(path) {
  let text

  try {
    text = readFileSync(path, 'utf8')
  } catch {
    return { purposes: {}, elements: {} }
  }

  const start = text.indexOf('= {')
  const end = text.lastIndexOf('} as const')

  if (start === -1 || end === -1) {
    throw new Error(`${path} is not in the expected shape - fix or delete it and re-run`)
  }

  const literal = text.slice(start + 2, end + 1)
  // eslint-disable-next-line no-new-func
  const value = new Function(`return (${literal})`)()

  return { purposes: value.purposes ?? {}, elements: value.elements ?? {} }
}

function renderFile(code, data) {
  const varName = `catalog${pascal(code)}`
  const doc = code === 'en' ? EN_DOC : OTHER_DOC

  const section = (kind) => {
    const keys = Object.keys(data[kind]).sort((a, b) => a.localeCompare(b))

    if (keys.length === 0) {
      return `  ${kind}: {},`
    }

    const rows = keys
      .map((key) => {
        const entry = data[kind][key]
        return [
          `    ${keyLiteral(key)}: {`,
          `      displayName: ${quote(entry.displayName ?? '')},`,
          `      description: ${quote(entry.description ?? '')},`,
          '    },',
        ].join('\n')
      })
      .join('\n')

    return `  ${kind}: {\n${rows}\n  },`
  }

  return [
    LICENSE,
    doc,
    `const ${varName} = {`,
    section('purposes'),
    section('elements'),
    '} as const',
    '',
    `export default ${varName}`,
    '',
  ].join('\n')
}

function main(catalog) {
  const sources = { purposes: new Map(), elements: new Map() }

  for (const purpose of catalog.purposes) {
    if (purpose.name) {
      sources.purposes.set(purpose.name, {
        displayName: purpose.displayName ?? '',
        description: purpose.description ?? '',
      })
    }
  }

  for (const element of catalog.elements) {
    if (element.name) {
      sources.elements.set(element.name, {
        displayName: element.displayName ?? '',
        description: element.description ?? '',
      })
    }
  }

  const total = sources.purposes.size + sources.elements.size
  console.log(
    `catalog: ${String(sources.purposes.size)} purposes, ${String(sources.elements.size)} elements`,
  )

  const codes = readdirSync(RESOURCES).sort((a, b) => a.localeCompare(b))
  let wrote = 0

  for (const code of codes) {
    const path = join(RESOURCES, code, 'catalog.ts')
    const existing = readExisting(path)
    const isEnglish = code === 'en'
    const merged = { purposes: {}, elements: {} }
    let translated = 0

    for (const kind of ['purposes', 'elements']) {
      // Server keys first, then anything already in the file that the server no
      // longer returns - older versions may still be referenced by a consent.
      const keys = new Set([...sources[kind].keys(), ...Object.keys(existing[kind])])

      for (const key of keys) {
        const source = sources[kind].get(key)
        const current = existing[kind][key] ?? {}

        merged[kind][key] = isEnglish
          ? {
              // English is regenerated from the server every run: it is a
              // report of what exists, not something anyone edits by hand.
              displayName: source?.displayName ?? current.displayName ?? '',
              description: source?.description ?? current.description ?? '',
            }
          : {
              displayName: current.displayName ?? '',
              description: current.description ?? '',
            }

        if (!isEnglish && String(merged[kind][key].displayName).trim()) {
          translated += 1
        }
      }
    }

    if (!checkOnly) {
      writeFileSync(path, renderFile(code, merged), 'utf8')
      wrote += 1
    }

    if (!isEnglish) {
      const missing = total - translated
      const status = missing === 0 ? 'complete' : `${String(missing)} missing`
      console.log(`  ${code.padEnd(4)} ${String(translated)}/${String(total)}  ${status}`)
    }
  }

  console.log(
    checkOnly ? '\nchecked only, no files written' : `\nwrote ${String(wrote)} catalog.ts files`,
  )
  console.log('run `pnpm lint:fix` to format them')
}

loadCatalog()
  .then(main)
  .catch((error) => {
    console.error(error.message)
    process.exitCode = 1
  })
