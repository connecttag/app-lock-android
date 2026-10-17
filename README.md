# App Lock Android

Android app-lock primitives for lock state, attempt tracking, biometric capability checks, and local state storage.

## Responsibilities

- Own app-lock models, manager logic, state store contracts, hashing helpers, and biometric capability checks.
- Provide default Android implementations that can be replaced in tests or consuming apps.
- Keep expected failures represented with result/state models rather than thrown generic exceptions.

## Boundaries

- Do not own app navigation, dialogs, or consuming app session policy.
- Do not store raw secrets or expose implementation details that prevent testing.
- Do not introduce Hilt directly into the base module; use an optional bridge if DI bindings are needed.

## Notes

- Uses `org.connecttag.kotlin.android`.
- Prefer constructor-injected interfaces for storage, clock/time, and platform capability collaborators.
