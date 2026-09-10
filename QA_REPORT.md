# Deep QA report — 2026-09-10

Baseline: clean checkpoint `be27a4c` (`Refine process and request form UX`). All changes remain uncommitted for review. This was functional QA, not a redesign or a dedicated security audit. Approved copy, colors, typography, page structure, methodology, service names and manual authorization model are preserved.

## Confirmed defects and fixes

| Defect / reproduction | Root cause | Smallest fix and coverage |
| --- | --- | --- |
| Exact-limit multiline system/objective text passed the browser but failed on submission. Example: 998 letters + LF + one letter in the 1000-character field. | Multipart transport changes LF into CRLF; the server counted two characters per newline. | Normalize line endings before multiline length validation. Limits remain unchanged. Unit tests cover all three multiline fields; browser tests submit individual and combined maximum lengths. |
| A failed POST replaced the form with the application error page, losing the draft. | A rejected Server Action transport escaped the form's error handling. | Catch transport failures in the hydrated submission path, retain values and show the existing inline failure copy. Preserve Next redirect control flow. Browser regression aborts the POST, checks retention, then successfully retries. |
| Returned server validation errors reset select/radio DOM values while React state and contextual copy retained old values. | React's automatic form reset also runs when an action returns business-validation errors. | Handle hydrated submission explicitly in a transition; retain the native action for progressive enhancement. A synchronous in-flight guard prevents duplicate POSTs. Regressions mutate a valid POST into an invalid environment and verify the actual select/radio values; double-click coverage verifies one POST. |
| Native submissions without JavaScript erased valid entries after a validation error. | The server returned errors without the submitted values; the next document initialized an empty form. | Return bounded, whitelisted scalar values and initialize the form from that action state. Tests correct an invalid email without re-entering other values and complete submission. Production-unavailable tests verify preservation in both JavaScript modes. |
| At 320 px with 200% text, header controls, service content and disclosure labels caused horizontal overflow. | Rigid flex/grid minimum sizes and long unbreakable words; sticky offsets assumed nominal header height. | Permit constrained wrapping/shrinking and measure the actual header height for scroll/menu offsets. No font or spacing tokens changed. Expanded-layout and enlarged-text browser regressions cover geometry and interaction. |
| WebKit produced a 342 px scroll area for the 320 px request page. | Native service-select layout contributed overflow outside its correctly sized 280 px control. CSS width/max-width/overflow alone did not fix it. | `contain: layout` isolates the native selector without replacing its appearance, arrow or popup. The 320 px baseline and expanded-form browser assertions remain in place. |
| Malformed configured contact strings such as `mailto:qa@example.test` and `<qa@example.test>` were accepted. | The previous regex accepted schemes and display-address punctuation as a mailbox. | Validate a plain mailbox with the existing Zod dependency and keep unavailable destinations omitted. Unit tests cover valid/empty/malformed values; rebuilt-page tests verify actual links and empty-wrapper absence. |
| The authority validation error had associated text but no programmatic invalid state. | The radio group omitted `aria-invalid`. | Give the fieldset the supported `radiogroup` role and group-level invalid state, retaining its legend and descriptions. Regression checks the named group after empty submission; Axe checks the error state. Individual radio elements do not support `aria-invalid` in the installed ARIA definitions. |

## Confirmed issues not changed

- The local Windows WebKit harness skips anchors when pressing Tab. This also reproduced with only a plain `<a>`, `<button>` and `<input>` in the document; Chromium/Firefox focus the anchor, while WebKit focuses the button. Alt+Tab did not enable link traversal in this harness either. Four existing/application keyboard assertions consequently remain failing in WebKit. They were not skipped, loosened or replaced by programmatic focus. No machine keyboard preferences were changed. Related upstream context: [Playwright issue 5609](https://github.com/microsoft/playwright/issues/5609).
- No remaining reproduced application defect is intentionally deferred. Native Safari and assistive-technology verification still require their actual environments.

## Suspected issues investigated

- The first Back/Forward probe navigated Back before the preceding client-side transition committed. Waiting for the destination URL reproduced the intended user sequence; no application history fix was needed.
- Rapid full-document unloads canceled Next prefetch requests. Firefox reported `NS_BINDING_ABORTED`; WebKit reported access-control console messages for the canceled prefetches. Network traces established the cancellation. The navigation test now lets requests settle before deliberately unloading documents and retains its zero-console-error/zero-failed-request assertions. No application error suppression was added.
- No hydration mismatch, unhandled application exception, broken internal route or serious asset-size issue was established in the completed normal runtime checks. This is a statement of observed coverage, not a universal guarantee.

## Coverage

- Chromium, Firefox and WebKit through real Playwright browser interaction against the optimized production build. Eight form regressions additionally run against the repository's existing development server.
- All five public routes, direct confirmation access, refresh, unknown/malformed routes and Turkish 404s; internal link destinations, section anchors and sticky offsets, service query defaults/preselection, repeated navigation and Back/Forward.
- Empty/partial/whitespace input, malformed email, Turkish characters, Unicode, apostrophes, quotes, ampersands, literal angle brackets, multiline text, exact limits and over-limit values. POST mutation bypasses browser checks and exercises authoritative server validation. Unit coverage also rejects duplicate fields, files and invalid enum values.
- Closed/populated optional disclosure, repeated keyboard toggles, conditional-provider removal/restoration and payload membership, authority/environment changes, Enter submission, returned errors, correction, transport failure/retry, double click, confirmation refresh/history and production-unavailable responses.
- Widths 320, 360, 375, 390, 430, 768, 1024, 1280, 1440 and 1920; 667×320 landscape and 320×1400 tall dimensions; 200% text at 320 and 640 px. Geometry checks include expanded methodology, multiple FAQs, mobile menus, validation summaries and optional fields. Representative screenshots supplement geometry assertions.
- Keyboard skip link, Tab order, Escape/menu focus restoration, leaving the nonmodal menu, independent disclosures, error-summary focus and error-link navigation. Native labels/legends, descriptions, named radio-group invalid state, visible outlines and reduced motion are checked. Axe covers primary pages and expanded/error form states; it is not a screen-reader certification.
- Rebuilt contact configuration: unset, empty, valid synthetic mailbox with surrounding whitespace, and malformed `mailto:` input. No address is sent mail. The final build restores the unconfigured contact state.
- Source/runtime sanity: client components remain limited to header, form and error boundary. No image/video assets or new runtime dependencies were added. The inspected build's ten JavaScript chunks total roughly 970 KiB raw / 269 KiB gzip across the whole build, not the initial page transfer. Resource timing attachments record actual browser loads. Fonts still come from the approved existing Google Fonts integration.

## Verification results

Completed checks:

- `npm.cmd run check`: lint, strict typecheck, 14 unit tests and production build passed.
- `QA_CROSS_BROWSER=true npm.cmd run test:e2e`: 105 cases executed; **101 passed, 4 failed**. Chromium 153.0.8010.12: **35/35**; Firefox 155.0: **35/35**; WebKit 26.6: **31/35**. All four failures are the independently reproduced Windows WebKit Tab-to-links limitation listed above. No tests were skipped, marked expected-failure or weakened. The WebKit native-select overflow regression passes.
- `QA_DEV=true npm.cmd run test:e2e -- release-form release-torture --project=chromium`: 8 passed. An initial attempt to launch a second development server correctly refused; QA then reused the existing server on port 3000.
- `npm.cmd run test:e2e -- --config=playwright.configuration.config.ts`: 3 passed for each of four rebuilt contact settings (12 total). Production demo acceptance was disabled in all four runs.
- `QA_CROSS_BROWSER=true npm.cmd run test:e2e -- release-runtime`: 3 passed after adding independent expanded-form Axe checks at desktop/mobile sizes. This completes that coverage in WebKit even though its earlier keyboard tests stop at the Tab assertions. Lint and typecheck passed again after the test addition.
- `git diff --check`: passed. Original `site.spec.ts` and `polish.spec.ts` assertions are unchanged. Generated `next-env.d.ts` build-path churn was restored to the checkpoint version.
- Temporary diagnostic probes were removed after establishing root causes; all application regression assertions remain.
- Desktop/mobile homepage, process and expanded-optional-form screenshots were visually inspected in Chromium and WebKit. The approved appearance, neutral process rules, readable helpers and visible focus remain intact. No horizontal overflow was detected in the final tested layouts, including enlarged text.

The test process emits a `NO_COLOR`/`FORCE_COLOR` conflict warning inherited from the runner environment. This is separate from browser/application console checks and was not suppressed. Next's build reports the existing Server Actions configuration as experimental; no new production warning was introduced.

## Files changed

- `src/app/globals.css`: wrapping, intrinsic sizing, native-select containment and actual-header offsets.
- `src/components/header.tsx`: actual-height observation and constrained toggle-label markup.
- `src/components/request-form.tsx`: submission error/state retention and radio-group invalid semantics.
- `src/app/test-talep-et/actions.ts`, `src/lib/request-schema.ts`: authoritative newline normalization and bounded values for native error responses.
- `src/lib/site-config.ts`, new `src/lib/contact-email.ts`: plain-mailbox configuration validation.
- `tests/request-schema.test.ts`: four additional boundary/configuration unit tests.
- New `tests/e2e/release-{form,layout,navigation,runtime,torture}.spec.ts`: regression, runtime and interaction coverage.
- New `tests/configuration/configuration.spec.ts`, `playwright.configuration.config.ts`: contact/build and production-guard scenarios.
- `playwright.config.ts`: opt-in Firefox/WebKit and development checks; aggregate timeout accommodates the expanded suite without weakening per-assertion limits.
- `README.md`, `QA_REPORT.md`: reproducible commands, findings and limitations.

## Remaining release risks

- The adapter is still deliberately a non-persistent demo. Real inquiry acceptance requires a durable backend, retry/idempotency behavior and operational monitoring before public launch. The production guard remains enabled by default.
- Confirmation is a directly accessible demo route with approved future receipt copy; it is not evidence that data was delivered. This approved MVP behavior was not changed.
- Final legal/privacy text, operator details, real contact/branding and the existing external-font privacy choice still require launch review.
- Native Safari/VoiceOver and real mobile devices are not available here. The Windows WebKit Tab limitation prevents a complete link-traversal sign-off in that harness. Chromium/Firefox keyboard tests and automated accessibility checks do not substitute for assistive-technology testing.
- This pass did not perform a penetration test, infrastructure audit, customer-target test or production load measurement.
