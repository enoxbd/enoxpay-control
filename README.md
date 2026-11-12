# Enox Pay Remote Control Plane

Centralized, cryptographically signed configuration repository for **Enox Pay** (`com.enox.enoxpay.bmdxyz`).

## How It Works
Edit any JSON file inside `control/` directly on GitHub. Within seconds, the **Sign Control Bundle** workflow validates the JSON, increments the monotonic anti-rollback `revision`, signs the canonical payload with `ENOX_CONTROL_SIGNING_KEY` (`SHA256withECDSA`, NIST P-256), and publishes `dist/signed_control.json`.

Enox Pay verifies the ECDSA signature using the pinned public key embedded in the APK before honoring any setting, preventing MITM spoofing, proxy tampering, and old-revision replay attacks.

## Control Files

- `control/app_status.json`: Global kill switch (`appEnabled: false` or `status: "closed"` disables UI and stops SMS, notification, and webhook services immediately), custom lockout message, `minActiveVersionCode`, and `disabledVersions`.
- `control/update.json`: Controls in-app updates (`latestVersionCode`, `latestVersionName`, `minSupportedVersionCode`, `forceUpdate`, `releaseNotes`, `downloadUrl`, and optional `apkSha256`).
- `control/features.json`: Remote switches for `smsCaptureEnabled`, `notificationCaptureEnabled`, `webhookSyncEnabled`, `manualTransactionEnabled`, `inboxExplorerEnabled`, `telegramBotEnabled`, `analyticsEnabled`, `backupRestoreEnabled`, and `maxRetryCount`.
- `control/announcement.json`: Live dashboard banner (`enabled`, `id`, `severity`, `title`, `message`, optional `actionLabel` / `actionUrl`, `dismissible`).
- `control/security.json`: Tamper/anti-bypass policy (`enforceSignatureVerification`, `blockOnTamper`, `blockFridaXposedHooks`, `offlineGraceMinutes`, `refreshIntervalMinutes`, `failClosedWhenUnverified`, `allowedAppCertSha256`).
