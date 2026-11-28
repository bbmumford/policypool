# Changelog

## [0.2.0](https://github.com/bbmumford/policypool/compare/v0.1.0...v0.2.0) (2026-11-28)


### Features

* an identity can be check-only, for a copy whose header its source stamped, and CheckIdentity checks the file behind a pool policypool did not open ([bd5c29e](https://github.com/bbmumford/policypool/commit/bd5c29e3137afd27c644034b3af95b12b2e9b5dd))


### Bug Fixes

* a busy checkpoint after a new file's first stamp is retried, then reported as ErrFileBusy, never as a file-identity refusal ([41c7aca](https://github.com/bbmumford/policypool/commit/41c7acad5965fa8b228f00a437290553f5adfd69))
* every new connection of an identity pool checks the kind of the file it opened, so a file replaced at the path is refused ([b4b370c](https://github.com/bbmumford/policypool/commit/b4b370c8acf26ba5d733b8ddd6230e06b634ee24))
* go.mod requires filekind v0.1.1, so the module builds without a workspace ([a9212a6](https://github.com/bbmumford/policypool/commit/a9212a61c5987de0c12f871af20117bc5392e58a))
* policypool requires filekind v0.1.2, whose header read takes both fields from one statement ([ec06af6](https://github.com/bbmumford/policypool/commit/ec06af66494e610c3b927e19ac15f5ac76294ee6))
