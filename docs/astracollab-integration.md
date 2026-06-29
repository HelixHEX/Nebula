# Astracollab Integration

Astracollab is the hosted product layer on top of Nebula.

## Responsibilities

Nebula owns:

- snapshots
- changesets
- refs
- proposals
- policies
- environments
- projections
- vector index manifests
- Git export plans

Astracollab owns:

- auth and org membership
- billing and credits
- tickets and projects
- agent runs and follow-ups
- review UI and comments
- notifications
- GitHub webhooks
- Vercel/GitHub integration configuration
- `astra` platform CLI

## Coding Agent Flow

```txt
Ticket
  -> Astracollab starts agent run
  -> agent edits sandbox
  -> Nebula captures snapshot
  -> Nebula creates ChangeSet
  -> Nebula creates Proposal
  -> Nebula evaluates policies
  -> Astracollab opens Review UI
  -> optional GitHub PR export
```

The current GitHub PR flow remains as the first compatibility export. Nebula should capture the changeset before the existing commit/push/PR step.

## Platform CLI

The `astra` CLI should call Astracollab APIs and delegate local source-control operations to `neb` where possible.

Example commands:

```bash
astra login
astra registry use
astra repo link
astra agent run TICK-123
astra review open proposal_123
astra env configure production
astra integration vercel
astra projection preview --environment production
astra export github proposal_123
```

## UI/API Surface

Astracollab run detail pages should eventually show:

- Nebula proposal status
- changed files
- private/public indicators
- environment access
- policy blockers
- projection previews
- GitHub export state
- Vercel deployment projection state
- vector context readiness
