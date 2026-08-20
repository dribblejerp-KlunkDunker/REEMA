# Upstream bug report: `ags update` crashes with `remote.map is not a function`

**Status:** ready to file — patch verified against `agentskill-sh/ags` @ `main`
**File against:** https://github.com/agentskill-sh/ags/issues/new
**Patch:** [`ags-update-remote-map.patch`](./ags-update-remote-map.patch) (applies cleanly to `src/commands/update.ts`)

---

## Summary

`ags update` crashes with `TypeError: remote.map is not a function` as soon as
any skill is installed and tracked in the lock file. The CLI assumes
`GET /agent/skills/version` returns an **array**, but the API returns an
**object keyed by slug** — so `remote.map(...)` throws before any update logic
runs. Every `ags update` (interactive and `--json`) is a hard crash, not a
graceful "up to date".

## Environment

- `@agentskill.sh/cli` 2.0.2 (npm global install; bug is present in the
  published dist and in `main` at `src/commands/update.ts:45`)
- Node 20.19+
- Reproduction requires ≥1 skill with a `contentSha` in the lock file (any
  skill installed via `ags install`)

## Reproduction

```bash
ags install some-skill
ags update
```

Expected: "All N skills up to date" (or an update prompt).
Actual:

```
✖ Failed to check versions
TypeError: remote.map is not a function
    at updateCommand (file:///.../dist/commands/update.js:32:28)
```

`ags update --json` crashes the same way.

## Root cause

`src/commands/update.ts` (and `dist/commands/update.js`) types the response as
an array and calls `.map()` on it:

```ts
let remote: VersionEntry[]
remote = await apiFetch<VersionEntry[]>(`/agent/skills/version?slugs=...`)
const remoteMap = new Map(remote.map((r) => [r.slug, r.contentSha]))
```

But the endpoint returns a keyed object:

```bash
$ curl -s 'https://agentskill.sh/api/agent/skills/version?slugs=agentskill-sh%2Flearn'
{
  "versions": {
    "agentskill-sh/learn": { "contentSha": "e6b59a3" }
  }
}
```

`remote` is `{ versions: {...} }` — an object, which has no `.map()`. The
`VersionEntry[]` type hides the mismatch from the compiler.

## Fix

Parse the keyed object instead of assuming an array (see
[`ags-update-remote-map.patch`](./ags-update-remote-map.patch)):

```ts
// GET /agent/skills/version returns an object keyed by slug, not an array.
interface VersionResponse {
  versions: Record<string, VersionEntry>
}

let remote: VersionResponse
remote = await apiFetch<VersionResponse>(`/agent/skills/version?slugs=...`)

const remoteMap = new Map(
  Object.entries(remote.versions).map(([slug, v]) => [slug, v.contentSha]),
)
```

## Verification performed

- Patch applies cleanly to a fresh `git clone --depth 1` of `agentskill-sh/ags`
  (`git apply --check` passes; also verified LF-normalized).
- The identical logic change was applied to the installed
  `dist/commands/update.js` and verified end-to-end against the live API:
  `ags update --json` → `{"updated":[],"upToDate":2}`, with the resolved map
  matching both lock-tracked skills' `contentSha`s exactly (outdated: 0) —
  proving the fix populates the map genuinely rather than silently reporting
  "up to date" on an empty map.

## Suggested follow-ups for maintainers

- Same array-vs-object assumption should be audited in other commands that
  consume `apiFetch` results (e.g. `list`, `find`).
- Consider adding a compile-time guard: `apiFetch` could validate the response
  shape and throw a descriptive error instead of a raw `TypeError` deep in a
  command.
