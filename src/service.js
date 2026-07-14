'use strict'
/**
 * [EN]    PAdES (PDF) signing — PKCS#12 pre-imported certificate.
 *         Uses native fetch + FormData (Node.js 18+) and JSZip.
 * [PT-BR] Assinatura PAdES (PDF) — certificado PKCS#12 pré-importado.
 *         Usa fetch + FormData nativos (Node.js 18+) e JSZip.
 */
const fs   = require('fs')
const path = require('path')
const JSZip = require('jszip')

/**
 * @param {object} opts
 * @param {string}   opts.authorization
 * @param {string}   opts.baseUrl
 * @param {string}   opts.pfxCode        - pre-imported certificate ID
 * @param {Array<{buffer: Buffer, filename: string}>} opts.files
 * @param {Array<{buffer: Buffer, filename: string}>} [opts.imageFiles]
 * @param {object}   opts.sigParams      - profile, hashAlgorithm, signatureFieldConfig, etc.
 * @returns {Promise<Buffer|null>}        ZIP buffer
 */
async function signPdfPkcs12({ authorization, baseUrl, pfxCode, files, imageFiles = [], sigParams = {} }) {
  const form = new FormData()
  files.forEach(({ buffer, filename }, i) => form.append(`document[${i}]`, new Blob([buffer]), filename))
  imageFiles.forEach(({ buffer, filename }, i) => form.append(`signatureImage[${i}]`, new Blob([buffer]), filename))

  form.append('pfxCode', pfxCode)
  appendSigParamsPdf(form, sigParams)

  const resp = await fetch(`${baseUrl.replace(/\/$/, '')}/solidsign/dsig/pdf/sign-pkcs12`, {
    method: 'POST',
    headers: { Authorization: authorization },
    body: form,
  })
  if (!resp.ok) { console.error(`SolidSign error ${resp.status}: ${await resp.text()}`); return null }

  const signResp = await resp.json()
  return downloadAndZip(signResp, files.map(f => f.filename), authorization)
}

// ── Batch (local files) ───────────────────────────────────────────────────────

async function signBatch() {
  const inputPath  = process.env.SOLIDSIGN_BATCH_INPUT_PATH ?? ''
  const outputPath = process.env.SOLIDSIGN_BATCH_OUTPUT_PATH ?? ''
  const pdfFiles   = fs.readdirSync(inputPath).filter(f => f.endsWith('.pdf'))

  if (!pdfFiles.length) { console.log(`No PDF files found in ${inputPath}`); return null }
  console.log(`Found ${pdfFiles.length} files for local processing.`)

  const files      = pdfFiles.map(f => ({ buffer: fs.readFileSync(path.join(inputPath, f)), filename: f }))
  const imagePaths = (process.env.SOLIDSIGN_SIGNATURE_IMAGE_PATHS ?? '').split(',').map(s => s.trim()).filter(Boolean)
  const imageFiles = imagePaths.filter(fs.existsSync).map(p => ({ buffer: fs.readFileSync(p), filename: path.basename(p) }))

  const zipBuf = await signPdfPkcs12({
    authorization: process.env.SOLIDSIGN_AUTHORIZATION,
    baseUrl:       process.env.SOLIDSIGN_BASE_URL,
    pfxCode:       process.env.SOLIDSIGN_CERT_ID,
    files, imageFiles,
    sigParams: {
      profile:                 process.env.SOLIDSIGN_PROFILE,
      hashAlgorithm:           process.env.SOLIDSIGN_HASH_ALGORITHM,
      policyVersion:           process.env.SOLIDSIGN_POLICY_VERSION,
      sigFieldMeasurementUnit: process.env.SOLIDSIGN_SIG_FIELD_MEASUREMENT_UNIT,
      signatureFieldConfig:    process.env.SOLIDSIGN_SIGNATURE_FIELD_CONFIG,
      reason:                  process.env.SOLIDSIGN_REASON,
      location:                process.env.SOLIDSIGN_LOCATION,
      contact:                 process.env.SOLIDSIGN_CONTACT,
    },
  })
  if (!zipBuf) return null

  if (!fs.existsSync(outputPath)) fs.mkdirSync(outputPath, { recursive: true })
  const outPath = path.join(outputPath, `signed_pdf_pkcs12_${Date.now()}.zip`)
  fs.writeFileSync(outPath, zipBuf)
  console.log(`PAdES PKCS12 signing complete. Output: ${outPath}`)
  return outPath
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function appendSigParamsPdf(form, p) {
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') form.append(k, String(v)) }
  add('profile', p.profile); add('hashAlgorithm', p.hashAlgorithm); add('policyVersion', p.policyVersion)
  add('sigFieldMeasurementUnit', p.sigFieldMeasurementUnit); appendIndexedJson(form, 'signatureFieldConfig', p.signatureFieldConfig)
  add('reason', p.reason); add('location', p.location); add('contact', p.contact)
  add('signatureFieldName', p.signatureFieldName); appendIndexedJson(form, 'signatureTextConfig', p.signatureTextConfig)
  add('mdpPermissionLevel', p.mdpPermissionLevel); add('passwordsForDecryption', p.passwordsForDecryption)
  add('documentInfoMetadata', p.documentInfoMetadata); appendIndexedJson(form, 'signatureQrCodeConfig', p.signatureQrCodeConfig)
}

async function downloadAndZip(signResp, originalNames, auth) {
  const zip = new JSZip()
  for (let i = 0; i < signResp.documents.length; i++) {
    const selfLink = signResp.documents[i]._links?.self || (signResp.documents[i].links || []).find(l => l.rel === 'self')
    if (!selfLink) continue
    const dlResp = await fetch(selfLink.href, { headers: { Authorization: auth } })
    if (!dlResp.ok) continue
    zip.file(`signed_${originalNames[i]}`, Buffer.from(await dlResp.arrayBuffer()))
  }
  return zip.generateAsync({ type: 'nodebuffer' })
}

// [EN]    Sends a visual-signature config as INDEXED fields: key[0], key[1], ...
//         The SolidSign API expects signatureFieldConfig[0]={...} per document,
//         NOT a single signatureFieldConfig=[{...}] — otherwise the field is ignored
//         and the visual stamp never appears.
// [PT-BR] Envia a config de assinatura visual como campos INDEXADOS: key[0], key[1], ...
//         A API espera signatureFieldConfig[0]={...} por documento, e NÃO um único
//         signatureFieldConfig=[{...}] — senão o campo é ignorado e o carimbo não aparece.
function appendIndexedJson(form, key, raw) {
  if (raw === undefined || raw === null || raw === '') return
  let parsed
  try { parsed = JSON.parse(raw) } catch (e) { form.append(`${key}[0]`, String(raw)); return }
  const items = Array.isArray(parsed) ? parsed : [parsed]
  items.forEach((it, i) => form.append(`${key}[${i}]`, typeof it === 'string' ? it : JSON.stringify(it)))
}

module.exports = { signPdfPkcs12, signBatch, appendSigParamsPdf, downloadAndZip }
