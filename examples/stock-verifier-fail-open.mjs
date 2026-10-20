// Reproduce electron-updater's built-in Windows verifier failing open.
// Run with: node examples/stock-verifier-fail-open.mjs <unsigned.exe>
//
// The stock verifier shells out with `set "PSModulePath=" & chcp 65001 >NUL & powershell.exe ...`.
// When the PowerShell call fails and the follow-up `ConvertTo-Json test` probe also fails,
// handleError() only logs a warning and the verifier resolves null, which NsisUpdater treats as
// "signature OK". Here PowerShell is made unreachable by clearing PATH for the call.
import updaterModule from 'electron-updater'
import { createStrictVerifier } from '../dist/index.js'

const file = process.argv[2]
if (!file) throw new Error('usage: node examples/stock-verifier-fail-open.mjs <unsigned-or-tampered.exe>')

const { NsisUpdater } = updaterModule
const forbidden = () => { throw new Error('must not install') }
const updater = new NsisUpdater(undefined, {
  version: '1.0.0', name: 'fail-open-demo', isPackaged: true,
  appUpdateConfigPath: '', userDataPath: process.env.TEMP, baseCachePath: process.env.TEMP,
  whenReady: async () => {}, quit: forbidden, relaunch: forbidden, onQuit: forbidden,
})
const warnings = []
updater.logger = { info() {}, warn: (m) => warnings.push(String(m)), error() {}, debug() {} }

const publisher = ['CN=Example Corp, O=Example Corp, C=US']
const savedPath = process.env.PATH
process.env.PATH = ''
try {
  const stock = await updater.verifyUpdateCodeSignature(publisher, file)
  console.log('stock verifier result:', stock === null ? 'null  (accepted)' : stock)
  console.log('stock verifier warning:', warnings[0]?.slice(0, 160) ?? '(none)')
} finally {
  process.env.PATH = savedPath
}
process.env.PATH = ''
try {
  console.log('strict verifier result:', await createStrictVerifier()(publisher, file))
} finally {
  process.env.PATH = savedPath
}
