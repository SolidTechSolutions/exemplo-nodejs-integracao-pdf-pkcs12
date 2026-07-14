'use strict'
/**
 * [EN]    PAdES (PDF) signing — PKCS#12 pre-imported certificate (Fastify / Node.js 18+).
 *         Setup: npm install && cp .env.example .env  (edit .env)
 *         Run:   npm start
 *         Batch: POST http://localhost:3088/api/pdf/sign-pkcs12
 *         Form:  POST http://localhost:3088/api/pdf/sign/form
 *
 * [PT-BR] Assinatura PAdES (PDF) — certificado PKCS#12 pré-importado (Fastify / Node.js 18+).
 *         Configurar: npm install && cp .env.example .env  (editar .env)
 *         Executar:   npm start
 */
require('dotenv').config()
const Fastify = require('fastify')
const { signPdfPkcs12, signBatch, appendSigParamsPdf } = require('./service')

const fastify = Fastify({ logger: true })
fastify.register(require('@fastify/multipart'))

// ── Batch endpoint ────────────────────────────────────────────────────────────
fastify.post('/api/pdf/sign-pkcs12', async (_req, reply) => {
  const inputPath = process.env.SOLIDSIGN_BATCH_INPUT_PATH ?? ''
  const require_fs = require('fs')
  if (!require_fs.existsSync(inputPath) || !require_fs.statSync(inputPath).isDirectory()) {
    return reply.status(400).send({ error: `Invalid input path: ${inputPath}` })
  }
  const outPath = await signBatch()
  if (!outPath) return reply.status(500).send({ error: 'Processing failed. Check logs.' })
  return { message: `Processing completed! ZIP generated at: ${outPath}` }
})

// ── Form endpoint ─────────────────────────────────────────────────────────────
fastify.post('/api/pdf/sign/form', async (request, reply) => {
  const parts = request.parts()
  const pdfFiles   = []
  const imageFiles = []
  const fields     = {}

  for await (const part of parts) {
    if (part.file) {
      const buf = await part.toBuffer()
      if (part.fieldname.startsWith('signatureImage')) {
        imageFiles.push({ buffer: buf, filename: part.filename })
      } else {
        pdfFiles.push({ buffer: buf, filename: part.filename })
      }
    } else {
      fields[part.fieldname] = part.value
    }
  }

  const zipBuf = await signPdfPkcs12({
    authorization: fields.authorization,
    baseUrl:       fields.baseUrl,
    pfxCode:       fields.pfxCode,
    files:         pdfFiles,
    imageFiles,
    sigParams:     fields,
  })

  if (!zipBuf) return reply.status(500).send({ error: 'Processing failed. Check logs.' })
  reply.type('application/zip').header('Content-Disposition', 'attachment; filename="signed_pdf.zip"')
  return zipBuf
})

fastify.listen({ port: Number(process.env.PORT ?? 3088), host: '0.0.0.0' }, err => {
  if (err) { fastify.log.error(err); process.exit(1) }
})
