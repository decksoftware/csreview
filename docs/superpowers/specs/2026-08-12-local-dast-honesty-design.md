# Local DAST Honesty and Privacy Design

**Status:** Approved

**Date:** 2026-08-12

## Purpose

Keep WebPoint-style development feedback safe and useful without allowing a failed or nonrepresentative HTTP probe to masquerade as a clean result or leak response secrets into reports.

## Preserved hard boundaries

- DAST requires explicit `--confirm-local-dast` consent.
- Targets must use HTTP(S), have no URL credentials, and resolve to `localhost`, `127.0.0.1`, or `[::1]`.
- Redirects use manual mode. A redirect to an external host aborts the phase.
- Requests are idempotent and never use mutating methods or payloads.
- Reports remain inside `<target>/csreview-reports/`.
- Built-in probes never emit `DAST-CONFIRMED`.

## Request model

`requestProbe(fetch, url, { method, headers })` performs one bounded request with manual redirects and returns status, an allowlisted/redacted header object, and a transport outcome.

The built-in suite sends:

1. a representative `GET` with `Accept: text/html` for browser security headers and CORS denial behavior;
2. an `OPTIONS` preflight with `Origin: https://csreview.invalid`, `Access-Control-Request-Method: GET`, and a benign requested header.

The implementation never consumes or persists the response body. It cancels the body when the runtime exposes a cancellable stream. A local redirect is reported as inconclusive unless the explicitly confirmed target itself can be assessed without following to a different route.

## Persisted evidence allowlist

Only these response headers may be written to a report:

- `content-security-policy`
- `x-content-type-options`
- `x-frame-options`
- `referrer-policy`
- `permissions-policy`
- `access-control-allow-origin`
- `access-control-allow-methods`
- `access-control-allow-headers`
- `access-control-allow-credentials`
- `vary`
- `location`
- `content-type`

All values pass through central redaction. `set-cookie`, `authorization`, authentication challenges, server tokens, and arbitrary application headers are never persisted. Commands and target URLs are sanitized before reporting.

## Result states

Built-in probes emit:

- `DAST-SUSPECTED`: representative evidence indicates a weak or risky policy;
- `DAST-CLEAN`: the representative request completed and the tested policy denied the unsafe condition or met the exact requirement;
- `DAST-INCONCLUSIVE`: the request could not establish either conclusion.

Network failure, timeout, 405/501 for the relevant method, 5xx, malformed response, redirect ambiguity, and an unsupported response shape are inconclusive. They never become clean.

## Header validation

Presence alone is insufficient:

- `X-Content-Type-Options` must equal `nosniff`.
- `X-Frame-Options` must equal `DENY` or `SAMEORIGIN` when CSP `frame-ancestors` is not the governing control.
- CSP must be nonempty and parsed conservatively. Wildcard `default-src` or `script-src`, or unsafe script execution without an appropriate nonce/hash control, is suspected.
- Empty or syntactically unusable Referrer-Policy and Permissions-Policy values are suspected.
- HSTS is not required for plain HTTP loopback development and is not used to create a false warning.

## CORS oracle

CORS evaluation combines the hostile-origin GET and OPTIONS results:

- wildcard origin, hostile-origin reflection, invalid credential/wildcard combinations, or an overly broad preflight response is suspected;
- a completed representative response that does not authorize the hostile origin is clean for this narrow check;
- missing evidence due to method errors, transport errors, or server failures is inconclusive.

The report describes this as one observed origin/method combination, never proof of the entire CORS policy.

## Environment preflight

External hosts found in local environment files remain advisory because development applications commonly reference them. Hostnames are redacted where necessary. The report warns that CSReview constrains only its own requests and cannot guarantee the local application will not contact an external dependency. No external URL is probed.

## Reporting

HTML and Markdown add visual/count support for `DAST-INCONCLUSIVE`. Each result includes the exact sanitized method, target, status, allowlisted headers, narrow conclusion, and remediation or retest instruction.

The CLI reports suspected, clean, and inconclusive counts separately. A DAST phase with only inconclusive checks is never described as successful.

## Verification

- The suite sends only GET and OPTIONS to the confirmed loopback target.
- External redirects abort; local redirect ambiguity is inconclusive.
- `Set-Cookie` and other nonallowlisted headers are absent from returned data and both reports.
- CSP `*`, X-Frame-Options `ALLOWALL`, empty policies, and hostile CORS reflection are suspected.
- OPTIONS 405/501, 5xx, timeout, and network failure are inconclusive.
- A representative successful response that denies the hostile origin is clean only for the stated CORS check.
- Existing confirmation, loopback, URL-credential, redirect, and report-output guards remain covered by regression tests.
