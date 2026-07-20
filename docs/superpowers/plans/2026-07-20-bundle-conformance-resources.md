# Bundle Conformance Resources Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the installed MissionWeaveProtocol Python wheel run all 56 conformance vectors without requiring a protocol checkout or `--root`.

**Architecture:** Package the complete `conformance/` tree beside the existing packaged schemas. Add one resolver that selects the installed package root first and the source checkout root second, while retaining explicit `--root` and current `--manifest` semantics. Verify source execution, custom-manifest compatibility, and a clean wheel installation from outside the repository.

**Tech Stack:** Python 3.12, Typer, Hatchling, pytest, uv, GitHub Actions

---

### Task 1: Specify packaged resources and CLI root selection

**Files:**
- Modify: `tests/test_package.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Add the failing package configuration assertion**

Add this assertion to `test_package_configuration_includes_typed_marker_and_complete_schema_directory`:

```python
assert force_include["conformance"] == "missionweaveprotocol/conformance"
```

- [ ] **Step 2: Add the failing default resource-resolution CLI test**

Add this test to `tests/test_cli.py`:

```python
def test_conformance_entrypoint_resolves_default_resources_outside_checkout(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.conformance_app)

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "56/56 conformance vectors passed"
```

At source-test time this exercises checkout fallback; Task 3's clean-wheel smoke test proves
that the resources are bundled in an installed distribution.

- [ ] **Step 3: Characterize `--manifest` without `--root`**

Add this compatibility test:

```python
def test_conformance_manifest_override_keeps_current_directory_as_root(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.example.test/custom.schema.json",
        "type": "object",
        "required": ["ok"],
        "properties": {"ok": {"const": True}},
        "additionalProperties": False,
    }
    instance = {"ok": True}
    manifest_entry = {
        "name": "custom-valid",
        "schema": "schemas/custom.schema.json",
        "instance": "vectors/custom.json",
        "valid": True,
    }

    schemas = tmp_path / "schemas"
    schemas.mkdir()
    (schemas / "custom.schema.json").write_text(json.dumps(schema), encoding="utf-8")
    vectors = tmp_path / "vectors"
    vectors.mkdir()
    (vectors / "custom.json").write_text(json.dumps(instance), encoding="utf-8")
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    manifest = manifests / "custom-manifest.json"
    manifest.write_text(json.dumps([manifest_entry]), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.conformance_app, ["--manifest", str(manifest)])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == "1/1 conformance vectors passed"
```

Keeping the manifest below `tmp_path/manifests/` makes its parent different from the current
directory, proving that `--manifest` alone remains rooted at the current directory. This test
must pass before implementation and remain green afterward.

- [ ] **Step 4: Run the focused tests and verify RED**

Run:

```bash
uv run pytest tests/test_package.py::test_package_configuration_includes_typed_marker_and_complete_schema_directory tests/test_cli.py::test_conformance_entrypoint_resolves_default_resources_outside_checkout tests/test_cli.py::test_conformance_manifest_override_keeps_current_directory_as_root -q
```

Expected: the package configuration and default resource-resolution tests fail for the two
missing features; the nested-manifest compatibility test passes.

- [ ] **Step 5: Commit the RED specification**

Run:

```bash
git add tests/test_package.py tests/test_cli.py docs/superpowers/plans/2026-07-20-bundle-conformance-resources.md
git commit -m "test(packaging): reproduce missing conformance bundle"
```

Expected: the branch records the verified failing tests before production changes.

### Task 2: Package and resolve the conformance bundle

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/missionweaveprotocol/conformance.py`
- Modify: `src/missionweaveprotocol/cli.py`

- [ ] **Step 1: Package the complete conformance directory**

Add this entry under `[tool.hatch.build.targets.wheel.force-include]`:

```toml
"conformance" = "missionweaveprotocol/conformance"
```

- [ ] **Step 2: Add package-first root resolution**

Add this function to `src/missionweaveprotocol/conformance.py`:

```python
def default_conformance_root() -> Path:
    """Locate a complete conformance bundle in an installed wheel or source checkout."""

    packaged = Path(__file__).resolve().parent
    if (packaged / "schemas").is_dir() and (packaged / "conformance" / "manifest.json").is_file():
        return packaged
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / "schemas").is_dir() and (checkout / "conformance" / "manifest.json").is_file():
        return checkout
    raise FileNotFoundError("MissionWeaveProtocol conformance resources are not installed")
```

- [ ] **Step 3: Preserve the three CLI root-selection cases**

Import `default_conformance_root` in `src/missionweaveprotocol/cli.py`, change the `root` option to `Path | None = None`, and resolve it with:

```python
if root is not None:
    resolved_root = root.resolve()
elif manifest is not None:
    resolved_root = Path.cwd().resolve()
else:
    resolved_root = default_conformance_root()
report = run_manifest(resolved_root, manifest.resolve() if manifest else None)
```

This keeps explicit `--root`, retains current `--manifest`-only behavior, and uses packaged defaults only when neither override is supplied.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run the Task 1 focused command again. Expected: `3 passed`.

- [ ] **Step 5: Commit the implementation**

Run:

```bash
git add pyproject.toml src/missionweaveprotocol/conformance.py src/missionweaveprotocol/cli.py
git commit -m "fix(packaging): bundle conformance resources"
```

Expected: the production change makes the committed RED tests pass.

### Task 3: Verify a clean installed wheel

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the wheel-install smoke step after `uv build`**

Add a CI step that creates a temporary virtual environment, installs `dist/*.whl`, changes to a directory outside the checkout, runs `missionweaveprotocol-conformance` without arguments, and checks for the exact line:

```text
56/56 conformance vectors passed
```

- [ ] **Step 2: Run the same smoke sequence locally**

Run:

```bash
uv build --wheel
test_root="$(mktemp -d)"
uv venv "$test_root/venv" --python 3.12
uv pip install --python "$test_root/venv/bin/python" dist/*.whl
output="$(cd "$test_root" && "$test_root/venv/bin/missionweaveprotocol-conformance")"
test "$output" = "56/56 conformance vectors passed"
```

Expected: exit code `0` and exact output match.

- [ ] **Step 3: Run repository verification**

Run:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run missionweaveprotocol-conformance --root .
```

Expected: all commands pass; pytest retains only the pre-existing Starlette/httpx warning.

- [ ] **Step 4: Commit the CI smoke test**

Run:

```bash
git add .github/workflows/ci.yml
git commit -m "ci(packaging): verify installed conformance bundle"
```

Expected: three focused Conventional Commits; the final branch is green and can be squash-merged under the PR title `fix(packaging): bundle conformance resources`.
