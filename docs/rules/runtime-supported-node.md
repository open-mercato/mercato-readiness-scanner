# The app pins a supported Node.js runtime

**Rule ID:** `runtime-supported-node`
**Severity:** Medium

Local, CI, image, and provider builds should use a supported Node.js major. The
scanner checks that `package.json` requires Node.js 24 or newer.

## Remediation

Keep the generated `engines.node` constraint, pin the same supported major in
the provider or image, and make deployment fail rather than silently selecting
an older runtime.

See [Installation prerequisites](https://docs.openmercato.com/installation/prerequisites).
