# Contributing to SignalMoat

Thanks for helping make apps safer.

## Contributor License Agreement (required)

Before your first pull request is merged you must agree to the project's
Contributor License Agreement (CLA). The CLA confirms that you have the right
to contribute your code and grants the project maintainer a licence to
distribute it, including under future licence terms. This keeps the project's
licensing options open as it grows.

<!-- TODO(maintainer): choose the CLA text (e.g. based on the Apache Individual
CLA) with legal advice, and wire up a CLA bot (such as CLA Assistant) before
accepting the first external contribution. -->

## Workflow

1. Open an issue describing the change for anything non-trivial.
2. Fork, create a branch, and add tests — every detection needs a test that
   shows it firing and a test that shows it staying quiet on normal traffic.
3. Run `pytest`, `ruff check src tests` and `mypy --ignore-missing-imports src`; if you touched
   `clients/`, also run `npm test` in `clients/node` and the .NET test runner (see the README).
4. Open a pull request.

## Design rules

- Fail open: an error inside SignalMoat must never break the protected app.
- Bounded resources: every tracker must have a size cap and expiry.
- No network calls to attacker-controlled destinations.
- Never log or alert with raw secrets, tokens or passwords.
- One engine: detection logic lives in `src/signalmoat/`. The Node and .NET packages stay thin
  clients of the decision API so every language behaves identically.
- Match on canonical paths (`signalmoat.paths`) so rules cannot be dodged with encoding tricks.
