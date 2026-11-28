"""The production witness workflow's own shell steps, run here on an anchor with nothing to witness yet. Before this
test, an anchor with no checkpoints failed every hourly run at `git add witness` (no such folder), so the alert fired
for a state that is not a fault."""

import shutil
import subprocess
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "witness.yml"


def step_script(name: str) -> str:
    """The `run: |` block of the step called `name`, without a YAML library (none is a dependency)."""
    lines = WORKFLOW.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {name}")
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    body = []
    indent = None
    for line in lines[run + 1:]:
        if line.strip() and indent is None:
            indent = len(line) - len(line.lstrip())
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:] if line.strip() else "")
    return "\n".join(body) + "\n"


def bash(script: str, cwd: Path, env: dict = None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-e", "-c", script], cwd=cwd, capture_output=True, text=True, env=env, timeout=60)


def anchor_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def test_an_anchor_with_no_checkpoints_is_a_clean_run(tmp_path):
    anchor_repo(tmp_path / "anchor")
    witness = bash(step_script("Witness every checkpoint not yet witnessed"), tmp_path, {"PATH": "/usr/bin:/bin"})
    assert witness.returncode == 0 and "nothing to witness" in witness.stdout
    add = bash(step_script("Add the new records to the anchor branch"), tmp_path / "anchor")
    assert add.returncode == 0, add.stderr
    assert "nothing to add" in add.stdout


def test_an_empty_checkpoints_folder_signs_nothing(tmp_path):
    anchor = anchor_repo(tmp_path / "anchor")
    (anchor / "checkpoints").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sigstore", "python"):  # stand-ins that record a call, so a call on no file is seen
        (bin_dir / tool).write_text(f"#!/bin/sh\necho {tool} \"$@\" >> {tmp_path}/calls\n")
        (bin_dir / tool).chmod(0o755)
    script = step_script("Witness every checkpoint not yet witnessed").replace("${{ github.repository }}", "o/r")
    done = bash(script, tmp_path, {"PATH": f"{bin_dir}:/usr/bin:/bin", "ROOT_KEY": "ab" * 32})
    assert done.returncode == 0, done.stderr
    calls = (tmp_path / "calls").read_text().splitlines()
    assert not any(c.startswith("sigstore") for c in calls)  # nothing signed for a pattern that matched no file
    assert any(c.startswith("python -m signet_anchor check-witness") for c in calls)


def test_the_steps_are_found():
    assert "git add witness" in step_script("Add the new records to the anchor branch")
    assert shutil.which("bash") and shutil.which("git")
