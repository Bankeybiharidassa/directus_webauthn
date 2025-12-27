# Client vs Server Contract Diff

| Area | Client expectation (`reactapp2`) | Server reality (`/webauthn`) | Notes |
| --- | --- | --- | --- |
| Base path | `/webauthn` only | `/webauthn` (legacy `/login/*` aliases preserved) | `/webauthn` is removed; use reverse proxy if legacy callers remain. |
| Authentication options | Response nested under `data.publicKey` with `attemptId` | Server responds `{ data: { attemptId, publicKey } }` | Shapes align; ensure attemptId forwarded to verify. |
| Drytest options | Same as authentication options | Same; limited to current user allowCredentials | Matching. |
| Verify payload validation | Client always sends `{ credential, attemptId? }` | Server accepts but needs explicit 400s for missing/invalid fields | Add stricter runtime validation to avoid TypeErrors. |
| Credentials list | Client reads `{ data: [...] }` | Server returns `{ data: [...] }` | Fields aligned; ensure collection exists. |

## Actions
- Enforce canonical base `/webauthn` in both client and server.
- Add explicit bad-payload guards in verify handlers to prevent `TypeError: e.replace is not a function` crashes.
- Provide rollout guidance for legacy `/webauthn` callers via reverse proxy.
