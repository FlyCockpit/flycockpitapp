---
title: Remote Client
description: Remote generation management, artifact access, authenticated download, and SVG preview.
---

Remote clients (web, native, or relayed daemon sessions) can manage generation
and download artifacts through authenticated, scope-checked routes. This page
documents the exact access model.

## Remote generation management

Remote generation management requires **Owner** or the exact-project
**ImageGenerationAdmin** capability. This scope authorizes generation
management only. It is **not**:

- terminal/session/file/artifact authority
- a standing generation grant
- transferable to another project

An `ImageGenerationAdmin` can list targets, submit jobs, fetch job status, and
request cancellation — subject to the same spend, grant, and health gates as a
local agent.

## Artifact access

Artifact metadata, thumbnails, and downloads require exact authorized
session/project access. There is no global artifact read. Access is checked per
request against the session and project that own the artifact.

## Authenticated download

Download handles are **opaque and authenticated**. A remote client receives a
handle, not a filesystem path or provider URL. The handle is validated against
the session and project before any byte is returned.

The following are **never** exposed as remote routes:

| Resource | Why |
| --- | --- |
| Provider URLs | Out of Cockpit's control; may expire or leak |
| ComfyUI server paths | Remote identifiers, not local paths |
| Daemon filesystem paths | Local authority only |
| Raw or quarantined bytes | Not validated for remote consumption |

## SVG downloads and preview

Sanitized SVG downloads are **attachment-only**. The response header forces a
download, not inline rendering. Preview is a **raster thumbnail** — the SVG is
rasterized for display, and the raw SVG is never inlined in a remote page. This
prevents inline SVG script execution in a browser context.

| Surface | SVG handling |
| --- | --- |
| Download | Attachment-only (sanitized SVG) |
| Preview | Raster thumbnail |
| Raw bytes | Never a remote route |

## Artifact copies and the remote client

A remote client may cache a **device copy** derived from an authenticated
download. The device copy is not canonical — the retained artifact is. If the
retained artifact is cleaned up, the device copy remains but is no longer
backed by Cockpit.

## What is never exposed

- Provider output URLs.
- ComfyUI server paths or filenames.
- Daemon-local filesystem paths.
- Raw or quarantined bytes without validation.
- Checksum or decode internals (only the result is returned).
