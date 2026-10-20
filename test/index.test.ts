import assert from 'node:assert/strict'
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { createStrictVerifier, publisherMatches, readAuthenticodeSignature, verifyUpdateCodeSignature } from '../src/index.ts'

describe('publisherMatches', () => {
  const subject = 'CN=Example Corp, O=Example Corp, L=Springfield, S=Oregon, C=US, SERIALNUMBER=1234'

  it('matches when the subject carries every attribute of the publisher DN', () => {
    assert.ok(publisherMatches(['CN=Example Corp, O=Example Corp, C=US'], subject))
    assert.ok(publisherMatches(['CN=Other', 'CN=Example Corp,O=Example Corp'], subject))
  })

  it('rejects a differing attribute', () => {
    assert.ok(!publisherMatches(['CN=Example Corp, O=Example Corp, C=CN'], subject))
    assert.ok(!publisherMatches(['CN=Example Corp, O=Evil Corp'], subject))
  })

  it('never matches a bare common name', () => {
    assert.ok(!publisherMatches(['Example Corp'], subject))
  })

  it('handles quoted values with commas, as Windows prints them', () => {
    const quoted = 'CN="ACME (CHINA) CO.,LTD.", O="ACME (CHINA) CO.,LTD.", C=CN'
    assert.ok(publisherMatches(['CN="ACME (CHINA) CO.,LTD.",O="ACME (CHINA) CO.,LTD.",C=CN'], quoted))
    assert.ok(!publisherMatches(['CN=ACME (CHINA) CO.'], quoted))
  })
})

const onWindows = process.platform === 'win32'
// A real NSIS executable with an embedded Authenticode signature. Override with
// STRICT_AUTHENTICODE_FIXTURE=<path> and STRICT_AUTHENTICODE_PUBLISHER=<full DN>.
const fixture = process.env.STRICT_AUTHENTICODE_FIXTURE
  ?? join(process.env.ProgramFiles ?? 'C:\\Program Files', 'nodejs', 'node.exe')

describe('real files', { skip: !onWindows && 'Windows only' }, () => {
  let directory = ''
  let publisher = ''

  before(async () => {
    directory = mkdtempSync(join(tmpdir(), 'strict-authenticode-'))
    const signature = await readAuthenticodeSignature(fixture)
    assert.equal(signature.status, 'Valid', `fixture ${fixture} must be validly signed`)
    publisher = process.env.STRICT_AUTHENTICODE_PUBLISHER ?? signature.subject!
  })
  after(() => { rmSync(directory, { recursive: true, force: true }) })

  /** Copies the fixture and applies a byte-level change to its PE image or signature. */
  function tampered(name: string, mutate: (bytes: Buffer) => void): string {
    const bytes = readFileSync(fixture)
    mutate(bytes)
    const target = join(directory, name)
    writeFileSync(target, bytes)
    return target
  }

  function certificateTable(bytes: Buffer): { entry: number; offset: number; size: number; firstSection: number } {
    const pe = bytes.readUInt32LE(0x3c)
    const optional = pe + 24
    const dataDirectory = optional + (bytes.readUInt16LE(optional) === 0x20b ? 112 : 96)
    const entry = dataDirectory + 8 * 4
    const sectionTable = optional + bytes.readUInt16LE(pe + 20)
    return { entry, offset: bytes.readUInt32LE(entry), size: bytes.readUInt32LE(entry + 4), firstSection: bytes.readUInt32LE(sectionTable + 20) }
  }

  it('accepts the signed file for its own publisher', async () => {
    assert.equal(await verifyUpdateCodeSignature([publisher], fixture), null)
  })

  it('accepts a path that looks like PowerShell syntax', async () => {
    const target = join(directory, "update '; & calc; $(whoami) `x.exe")
    copyFileSync(fixture, target)
    assert.equal(await verifyUpdateCodeSignature([publisher], target), null)
  })

  it('rejects another publisher', async () => {
    assert.match(String(await verifyUpdateCodeSignature(['CN=Someone Else, O=Someone Else, C=US'], fixture)), /does not match/)
  })

  it('rejects a bare common name even when it equals the signer CN', async () => {
    const cn = /CN=("[^"]*"|[^,]*)/.exec(publisher)?.[1]?.replace(/^"|"$/g, '') ?? ''
    assert.ok(cn.length > 0)
    assert.match(String(await verifyUpdateCodeSignature([cn], fixture)), /bare common names/)
  })

  it('rejects a modified PE image (HashMismatch)', async () => {
    const target = tampered('pe-digest.exe', (bytes) => {
      const { firstSection } = certificateTable(bytes)
      bytes[firstSection + 64] = bytes[firstSection + 64]! ^ 1
    })
    assert.match(String(await verifyUpdateCodeSignature([publisher], target)), /status (HashMismatch|NotSigned|UnknownError)/)
  })

  it('rejects a modified signature blob', async () => {
    const target = tampered('cms.exe', (bytes) => {
      const { offset, size } = certificateTable(bytes)
      const at = offset + size - 64
      bytes[at] = bytes[at]! ^ 1
    })
    assert.match(String(await verifyUpdateCodeSignature([publisher], target)), /status /)
  })

  it('rejects a file whose signature was stripped (NotSigned)', async () => {
    const target = tampered('unsigned.exe', (bytes) => {
      const { entry } = certificateTable(bytes)
      bytes.fill(0, entry, entry + 8)
    })
    assert.match(String(await verifyUpdateCodeSignature([publisher], target)), /status NotSigned/)
  })

  it('rejects a catalog-signed system file unless catalog signatures are allowed', async () => {
    const notepad = join(process.env.SystemRoot!, 'System32', 'notepad.exe')
    const signature = await readAuthenticodeSignature(notepad)
    if (signature.type !== 'Catalog') return
    const microsoft = signature.subject!
    assert.match(String(await verifyUpdateCodeSignature([microsoft], notepad)), /signature type Catalog/)
    assert.equal(await createStrictVerifier({ allowCatalogSignature: true })([microsoft], notepad), null)
  })

  it('fails closed on a missing file without leaking the path', async () => {
    const result = await verifyUpdateCodeSignature([publisher], join(directory, 'not-present-secret-name.exe'))
    assert.ok(result !== null)
    assert.ok(!result.includes('not-present-secret-name'))
  })

  it('fails closed when PowerShell cannot be started', async () => {
    const saved = process.env.SystemRoot
    process.env.SystemRoot = join(directory, 'no-windows-here')
    try {
      const reasons: string[] = []
      const result = await createStrictVerifier({ onReject: (reason) => reasons.push(reason) })([publisher], fixture)
      assert.ok(result !== null)
      assert.equal(reasons.length, 1)
    } finally {
      process.env.SystemRoot = saved
    }
  })

  it('plugs into electron-updater as NsisUpdater.verifyUpdateCodeSignature', async () => {
    const { NsisUpdater } = (await import('electron-updater')).default
    const forbidden = () => { throw new Error('must not install') }
    const updater = new NsisUpdater(undefined, {
      version: '1.0.0', name: 'strict-authenticode-test', isPackaged: true,
      appUpdateConfigPath: '', userDataPath: directory, baseCachePath: directory,
      whenReady: async () => {}, quit: forbidden, relaunch: forbidden, onQuit: forbidden,
    } as never)
    updater.verifyUpdateCodeSignature = verifyUpdateCodeSignature
    assert.equal(await updater.verifyUpdateCodeSignature([publisher], fixture), null)
    assert.notEqual(await updater.verifyUpdateCodeSignature(['CN=Someone Else, O=Someone Else'], fixture), null)
  })
})
