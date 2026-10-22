# Production apps are created with create-mercato-app

**Rule ID:** `runtime-standalone-application`
**Type:** Invalid-target guard (exit code 2)

The Open Mercato monorepo is not a valid way to start a production app. It is a
framework development workspace; production applications must be created with
`create-mercato-app`.

Detection walks the target's parent directories, including when the target is
the internal application or a package. It checks workspace metadata and the
`@open-mercato/core` package under `packages/core`, together with either the
`open-mercato` root package identity or the `create-mercato-app` package under
`packages/create-app`. A workspace alone does not identify the framework
monorepo, and renaming the checkout directory does not bypass detection.

This guard rejects the target before running readiness rules, querying Git, or
writing reports. Its diagnostic always names `create-mercato-app`, including
with `--fail-on never` and every output format. It does not add a result to the
version 1 JSON report or change its schema.

## Remediation

Create a standalone application using `create-mercato-app`, migrate your custom
modules and application configuration, and run this scanner against the
generated application. Do not deploy the monorepo's internal app as the
production application.

Detection reads only bounded local package manifests. It does not run any
application or generator scripts, read secrets, or verify live infrastructure.
