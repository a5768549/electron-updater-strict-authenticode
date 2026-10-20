# electron-updater-strict-authenticode

A fail-closed `verifyUpdateCodeSignature` for [electron-updater](https://www.electron.build/auto-update)'s Windows `NsisUpdater`. An update is installed only when Windows reports the installer's Authenticode signature as **Valid** and the signer carries the full publisher DN you configured. Anything that cannot be proven valid is rejected.

```text
$ node examples/stock-verifier-fail-open.mjs unsigned.exe
stock verifier result: null  (accepted)
stock verifier warning: Cannot execute ConvertTo-Json: Command failed: set "PSModulePath=" & chcp 65001 >NUL & powershell.exe ...
strict verifier result: update signature rejected: status NotSigned
```

The demo hands an installer with its signature stripped to electron-updater 6.8.9's built-in verifier while `powershell.exe` cannot be found on `PATH`. The built-in verifier accepts it.

## What the built-in verifier does

`electron-updater/out/windowsExecutableCodeSignatureVerifier.js` (6.8.9):

| Situation | Built-in | This package |
|---|---|---|
| `powershell.exe` fails and a `ConvertTo-Json` probe also fails (not on `PATH`, blocked, broken install) | logs a warning, **resolves `null` = accepted** | rejected |
| Windows 7 / 8 (`os.release()` 6.0–6.2) and the PowerShell call fails for any reason | logs a warning, **accepted** without running the probe | rejected |
| `publisherName` is a bare common name (`Example Corp`) | accepted if it equals the signer's CN, with a warning | rejected; configure the full DN |
| PowerShell located through `PATH` and started via `cmd.exe` (`shell: true`) | yes | absolute `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, no shell |
| File path quoting | path is embedded in the command with `'` doubled | path passed in an environment variable, script passed with `-EncodedCommand` |
| Signature is a Windows catalog signature, not embedded | accepted if `Valid` | rejected by default (`allowCatalogSignature` to allow) |

Signature status checks themselves are the same: both require `Status = Valid` from `Get-AuthenticodeSignature`. DNs are compared with electron-updater's own `parseDn`, so a `publisherName` that already works keeps matching.

## Install

```sh
npm install electron-updater-strict-authenticode
```

`builder-util-runtime` is a peer dependency; it is already installed with `electron-updater`.

## Usage

```js
import { autoUpdater } from 'electron-updater'
import { verifyUpdateCodeSignature } from 'electron-updater-strict-authenticode'

if (process.platform === 'win32') {
  autoUpdater.verifyUpdateCodeSignature = verifyUpdateCodeSignature
}
```

`publisherName` comes from your electron-builder config (`win.signtoolOptions.publisherName`, written into `app-update.yml`). Set it to the **full subject DN** of your signing certificate, as Windows prints it:

```powershell
(Get-AuthenticodeSignature .\dist\YourApp-Setup.exe).SignerCertificate.Subject
# CN=Example Corp, O=Example Corp, L=Springfield, S=Oregon, C=US
```

Every attribute you list must match. Listing `CN`, `O` and `C` is a reasonable minimum.

### Options

```js
import { createStrictVerifier } from 'electron-updater-strict-authenticode'

autoUpdater.verifyUpdateCodeSignature = createStrictVerifier({
  timeoutMs: 60_000,               // PowerShell time limit
  allowCatalogSignature: false,    // accept catalog-signed files
  onReject: (reason) => log.warn(`update rejected: ${reason}`),
})
```

The returned message never includes the file path.

### Other exports

- `readAuthenticodeSignature(path)` → `{ status, type, subject }` from `Get-AuthenticodeSignature`.
- `publisherMatches(publisherNames, subject)` → whether `subject` carries every attribute of one of the names.

## Tested against

On Windows 10 with real files:

- a signed NSIS executable and `node.exe` → accepted for their own publisher, rejected for any other;
- the same files with one PE byte flipped → `HashMismatch`, rejected;
- with one byte of the signature blob flipped → `UnknownError`, rejected;
- with the certificate table entry zeroed → `NotSigned`, rejected;
- a catalog-signed `notepad.exe` → rejected, accepted with `allowCatalogSignature`;
- a path like `update '; & calc; $(whoami) .exe` → verified as a literal path;
- `SystemRoot` pointing nowhere → rejected;
- assigned to a real `NsisUpdater` from electron-updater 6.8.9.

Run them with `npm test`; set `STRICT_AUTHENTICODE_FIXTURE` to test against your own installer.

## What it does not do

- It does not check revocation beyond what `Get-AuthenticodeSignature` does, and it does not pin a certificate thumbprint. If you need that, call `readAuthenticodeSignature` in your own wrapper and compare against the thumbprint as well.
- It is Windows-only; on other platforms it rejects, so only assign it on `win32`.

## License

[MIT](LICENSE)
