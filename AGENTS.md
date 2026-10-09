# Agent guidelines

## Always

- Keep the scanner read-only with respect to the scanned application.
- Production `.env` files and relevant process environment variables may be read locally for configuration checks, as explicitly authorized by the user. Never execute them or include their values in reports or diagnostics.
- Never read private-key files, token caches, or external secret stores. Service credentials are checked only in the authorized environment configuration.
- Keep findings deterministic and evidence free of secret values and absolute home paths.
- Give every rule a stable ID and its own matching `docs/rules/<rule-id>.md` page.
- Preserve the JSON schema version and document incompatible report changes.
- Run `npm run check` before committing.

## Ask First

- Ask before publishing to npm, making the repository public, or adding a runtime dependency.
- Ask before adding active network probes or executing code from a scanned application.

## Never

- Never execute target application scripts.
- Never upload scan results or target files.
- Never claim that a static check proves live infrastructure state.
