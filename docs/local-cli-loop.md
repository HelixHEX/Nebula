# Local CLI Loop

Phase 3 gives `neb` a real local workflow before remote registry sync exists.

## Storage Layout

`neb init` creates:

```txt
.nebula/
  config.json
  refs.json
  workspaces/
    active
    main.json
  objects/
    blobs/
    snapshots/
    changesets/
    proposals/
    operations/
    policies/
    environments/
    integrations/
    secrets/
```

The blob store is content-addressed using `ContentHash::object_path()`.

## Ignoring Paths

Nebula always excludes its own metadata and a small set of common build
directories (`.nebula`, `.git`, `node_modules`, `.next`, `.turbo`, `target`,
etc.), no matter how deeply nested they are.

You can add repository-specific exclusions from two places, layered on top of
the built-in defaults:

- The `ignore` array in `.nebula/config.json`.
- A root `.nebignore` file, using gitignore-style syntax (`#` comments, `!`
  negation, trailing `/` for directory-only patterns). `.nebignore` is applied
  last, so it can override both the defaults and `config.json` — for example
  `!some/default/ignored/path` un-ignores a path that would otherwise be
  skipped.

`status`, `diff`, and `save` all honor these rules when scanning the working
tree.

## Commands

Initialize local metadata:

```bash
neb init
```

Inspect changes in the active workspace:

```bash
neb status
neb diff
```

Save current working tree state as a canonical snapshot and changeset:

```bash
neb save --message "Implement auth redirect"
```

Create and manage local workspaces:

```bash
neb workspace create auth-fix --from main
neb workspace list
neb workspace switch auth-fix
```

Create a local protocol-level proposal:

```bash
neb propose --target main --title "Fix auth redirect"
neb proposal list
neb proposal status <proposal-id>
neb proposal close <proposal-id>
neb merge <proposal-id>
neb ref list
neb ref show main
```

## Current Constraints

- `status`, `diff`, and `save` scan the current working tree in this local-only phase.
- `push`, `pull`, and `clone` support local file-backed Nebula sync bundles. Network registry sync is the next transport layer.
- `save` records workspace-local snapshots and changesets; `merge` advances the target ref only when it can fast-forward.
- `workspace switch` changes the active Nebula workspace pointer but does not yet materialize that snapshot into the OS filesystem.
- `policy`, `env`, `integration`, `secret`, `vector`, and `projection` commands now create local protocol metadata or local projections, but hosted provider behavior is still separate.

Future phases should replace full working-tree scans with dirty-path tracking via a persistent overlay catalog and filesystem monitoring.
