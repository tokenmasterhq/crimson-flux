## Summary

Describe the user-visible or release-boundary change.

## Verification

- [ ] `python scripts/check_skeleton.py`
- [ ] `python scripts/doctor.py`
- [ ] `python scripts/verify_g1.py --output dist/g1/g1-native.json`
- [ ] `uv run pytest`
- [ ] `uv run ruff check src tests scripts`
- [ ] `docker compose config`

## Security and scope

- [ ] No Cookie, token, real export or `.env` was committed.
- [ ] No comments, media downloading, publishing, model integration or proxy bypass was added.
- [ ] User-provided profile URLs remain restricted to approved HTTPS hosts.
- [ ] Server-issued content does not gain a new code-execution path.
- [ ] Server responses cannot reach dynamic Python/JavaScript execution, browser automation, or an external helper process.
- [ ] Source, Source ZIP, container and reachable Git history contain no retired vendor code or provenance markers.
- [ ] If this PR affects public live collection, the G1 approval record is referenced privately and the `live-release` reviewers are notified.
