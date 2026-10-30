# App integrity checks

[Back to the README](../../README.md)

**App integrity**: the installed app files are intact, signed by the key Android reports for the
app, and not renamed or cloned.

| Id | DETECTED means |
|---|---|
| `TAMPER_APK_CONTENT` | An installed APK file (the base or any split) no longer matches its own signature, or no signing entry in it carries a signer Android reports for the app. |
| `TAMPER_SIGNING_BLOCK` | No signing entry inside base.apk, read by native code with direct system calls, carries a signer Android reports for this app. So Android's answer, or the file, was faked or swapped. |
| `TAMPER_PUBLIC_KEY` | The app is signed with a key anyone can download: a public AOSP test key, or a key that ships inside a common re-signing tool (uber-apk-signer and others). |
| `TAMPER_REPACKAGER` | The APK holds files left by LSPatch or App Cloner. |
| `CLV_PKGNAME_MISMATCH` | The running package name differs from the application id written into the manifest when the app was built, so the app was renamed or cloned. |

Three more app-integrity results are INCONCLUSIVE, not DETECTED, so they never close the app on
their own: `NATIVE_CORE` (the native library did not load, so the native checks could not run),
`CHECK_STALLED` (no check made progress for 5 s, or an earlier run is stuck) and `CHECK_FAILED`
(the run could not start, or it stopped with an error).
