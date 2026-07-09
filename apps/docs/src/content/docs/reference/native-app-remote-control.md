---
title: Native App Remote Control
---

# Native App Remote Control

The Expo native app is a paid remote-control client for hosted Flycockpit and licensed enterprise deployments. OSS self-hosted servers should use the web app as a PWA; the native app verifies `/api/meta/profile` and refuses OSS or invalid enterprise profiles before exposing remote-control workflows.

## Manual E2E

1. Start the API, relay, and a `cockpit-cli` instance signed in to a hosted Pro or licensed enterprise account.
2. Set `apps/native/.env` `EXPO_PUBLIC_SERVER_URL` to the hosted or enterprise server origin, without a path or query string.
3. Run `pnpm doctor:native`, then `pnpm native:ios` or `pnpm native:android`.
4. Sign in on the Account tab.
5. Open the Instances tab and verify owned instances and accepted shared instances appear with presence. Keep the app foregrounded and verify web/browser notifications for the same user are suppressed by native presence heartbeat.
6. Open an instance, wait for the relay status to become `CONNECTED`, and open a project.
7. Select a session, send a message, and verify it appears in the CLI session. Leave the session open and verify new assistant text streams in without pressing Refresh.
8. Trigger an approval in the CLI, background the app, and verify an Expo push notification arrives.
9. Tap the notification, open the project/session deep link, then approve or deny the interrupt and verify the CLI proceeds.

The notification tap should take less than 10 seconds from push open to approval on a healthy network.

## OSS Refusal Check

Point `EXPO_PUBLIC_SERVER_URL` at a local OSS self-hosted server and reload the app. The Instances tab should show the native-app unavailable state and should not expose remote-control actions.

## Push Notes

Native devices register Expo push tokens through `push.registerNative`. Token rotation is handled on app start after sign-in, unregistering disables the token, and server delivery prunes `DeviceNotRegistered` tokens. APNs/FCM credentials are managed by Expo/EAS for store builds; local simulator behavior depends on the simulator and platform notification support.

## Current Cutline

The v1 native app supports server eligibility checks, entitlement gating, instances, shared-with-me instances, project/session browsing, live transcript streaming, text messages, clipboard-assisted composer text, and approval/question interrupt cards. Image attachment upload is intentionally disabled until the remote-session protocol exposes a real upload path; the app must not send local image URIs as message text. Terminal and file-browser surfaces remain separate follow-up work.
