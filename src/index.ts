/**
 * Fail-closed Windows Authenticode verification for electron-updater.
 *
 * electron-updater's built-in Windows verifier skips signature validation
 * (and lets the update install) when PowerShell is too old or `ConvertTo-Json`
 * cannot run, and it accepts a bare common name with only a warning. This
 * verifier rejects every case it cannot positively prove valid.
 */

import { execFile } from 'node:child_process'
import { join, resolve } from 'node:path'
// electron-updater's own RFC 2253 parser, so publisher names match exactly as
// electron-builder writes them into app-update.yml.
import { parseDn } from 'builder-util-runtime'

/**
 * Whether a signer subject carries every attribute of one of the expected
 * publisher names, compared with electron-updater's own DN parser. A publisher
 * name without any `KEY=value` attribute (a bare common name) never matches:
 * configure the full DN. electron-updater accepts a bare CN with a warning.
 */
export function publisherMatches(publisherNames: readonly string[], subject: string): boolean {
  const signer = parseDn(subject)
  return publisherNames.some((name) => {
    const expected = parseDn(name)
    return expected.size > 0 && [...expected].every(([key, value]) => signer.get(key) === value)
  })
}

const SIGNATURE_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$signature = Get-AuthenticodeSignature -LiteralPath $env:STRICT_AUTHENTICODE_FILE
[pscustomobject]@{
  status = [string]$signature.Status
  type = [string]$signature.SignatureType
  subject = $signature.SignerCertificate.Subject
} | ConvertTo-Json -Compress
`

/** What `Get-AuthenticodeSignature` reported for a file. */
export type AuthenticodeSignature = {
  /** `Valid`, `NotSigned`, `HashMismatch`, `NotTrusted`, `UnknownError`, ... */
  readonly status: string
  /** `Authenticode`, `Catalog` or `None`. */
  readonly type: string
  readonly subject: string | null
}

export type StrictVerifierOptions = {
  /** Maximum time for PowerShell, in milliseconds. Default 60 000. */
  timeoutMs?: number
  /**
   * Accept files whose signature comes from a Windows security catalog
   * instead of an embedded Authenticode signature. Installers are embedded-
   * signed, so the default is `false`.
   */
  allowCatalogSignature?: boolean
  /** Receives the reason for each rejection; never receives the file path. */
  onReject?: (reason: string) => void
}

const SECRET_NAME = /(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/iu

/**
 * Reads the Authenticode signature of a file with the system Windows PowerShell.
 *
 * The file path travels in an environment variable and the script is passed
 * with `-EncodedCommand`, so no part of the path is interpreted as PowerShell.
 * PowerShell is started from `%SystemRoot%\System32` by absolute path with
 * `PSModulePath` and `NODE_OPTIONS` removed and secret-looking variables
 * stripped from its environment.
 */
export function readAuthenticodeSignature(filePath: string, timeoutMs = 60_000): Promise<AuthenticodeSignature> {
  const systemRoot = process.env.SystemRoot
  if (systemRoot === undefined) return Promise.reject(new Error('SystemRoot is not set'))
  const environment: NodeJS.ProcessEnv = {}
  for (const [name, value] of Object.entries(process.env)) {
    if (name === 'NODE_OPTIONS' || name.toUpperCase() === 'PSMODULEPATH' || SECRET_NAME.test(name)) continue
    environment[name] = value
  }
  environment.STRICT_AUTHENTICODE_FILE = resolve(filePath)
  const powershell = join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  return new Promise((resolvePromise, reject) => {
    execFile(powershell, [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-EncodedCommand', Buffer.from(SIGNATURE_SCRIPT, 'utf16le').toString('base64'),
    ], { env: environment, timeout: timeoutMs, windowsHide: true, maxBuffer: 256 * 1024 }, (error, stdout) => {
      // A PowerShell error exits nonzero; stderr also carries harmless module-load progress records.
      if (error) {
        reject(new Error(`Get-AuthenticodeSignature failed (exit ${String((error as { code?: unknown }).code)})`))
        return
      }
      try {
        const parsed = JSON.parse(stdout) as { status?: unknown; type?: unknown; subject?: unknown } | null
        resolvePromise({
          status: typeof parsed?.status === 'string' ? parsed.status : 'Unknown',
          type: typeof parsed?.type === 'string' ? parsed.type : 'Unknown',
          subject: typeof parsed?.subject === 'string' ? parsed.subject : null,
        })
      } catch {
        reject(new Error('Get-AuthenticodeSignature returned unreadable output'))
      }
    })
  })
}

/**
 * Builds a `verifyUpdateCodeSignature` function for electron-updater's `NsisUpdater`.
 *
 * It accepts a downloaded installer only when Windows reports the Authenticode
 * signature as `Valid` and the signer subject carries every attribute of one
 * configured publisher DN. Any failure to run or parse PowerShell is a
 * rejection.
 *
 * @returns `null` to accept; a fixed message (without the file path) to reject.
 */
export function createStrictVerifier(options: StrictVerifierOptions = {}): (publisherNames: string[], filePath: string) => Promise<string | null> {
  const reject = (reason: string): string => {
    options.onReject?.(reason)
    return `update signature rejected: ${reason}`
  }
  return async (publisherNames, filePath) => {
    if (process.platform !== 'win32') return reject('not running on Windows')
    if (!publisherNames.some((name) => parseDn(name).size > 0)) {
      return reject('no publisher distinguished name is configured (bare common names are not accepted)')
    }
    let signature: AuthenticodeSignature
    try {
      signature = await readAuthenticodeSignature(filePath, options.timeoutMs)
    } catch (error) {
      return reject(error instanceof Error ? error.message : 'signature could not be read')
    }
    if (signature.status !== 'Valid') return reject(`status ${signature.status}`)
    if (signature.type !== 'Authenticode' && !(options.allowCatalogSignature && signature.type === 'Catalog')) {
      return reject(`signature type ${signature.type}`)
    }
    if (signature.subject === null || !publisherMatches(publisherNames, signature.subject)) {
      return reject('signer does not match the configured publisher')
    }
    return null
  }
}

/** The default strict verifier: `createStrictVerifier()` with default options. */
export const verifyUpdateCodeSignature = createStrictVerifier()
