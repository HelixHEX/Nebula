# Policy Model

Nebula policies answer one question:

```txt
Can actor X perform action A on object Y in environment Z?
```

## Actors

```txt
user:<id>
team:<id>
agent:<id>
integration:<id>
public
```

Integrations are actors. Vercel, GitHub, CI, Cursor, and deploy bots should not bypass the policy system.

## Environments

Default environments:

- `development`
- `staging`
- `production`

Custom environments can model security embargoes, enterprise customer deployments, demos, or public OSS projections.

## Actions

Core actions:

- `read_blob`
- `read_path`
- `write_changeset`
- `approve_changeset`
- `merge_changeset`
- `export_git`
- `read_secret`
- `inject_secret`
- `read_build_source`
- `create_projection`
- `deploy`

## Decisions

Policy decisions:

- `allow`
- `redact`
- `template`
- `omit`
- `block`
- `embargo`

Git export and deployment projection should fail closed when no policy matches.

## Example

```txt
.env.production
  actor: integration:vercel
  environment: production
  action: inject_secret
  decision: allow

.env.production
  actor: integration:github
  environment: production
  action: read_blob
  decision: block

packages/proprietary-engine/**
  actor: integration:vercel
  environment: production
  action: read_build_source
  decision: allow
```
