import os
import shutil
import subprocess


def test_runner_executes_once_and_refuses_dirty_tree(tmp_path):
    root = tmp_path / "repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy("scripts/agent-runner.sh", scripts / "agent-runner.sh")
    (root / ".gitignore").write_text("data/\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake = fake_bin / "codex"
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\ncat\n')
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
    runner = scripts / "agent-runner.sh"
    result = subprocess.run([runner], cwd=root, env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0
    logs = list((root / "data/agent-runner").glob("*.log"))
    assert len(logs) == 1
    assert "--sandbox workspace-write" in logs[0].read_text()
    assert "Do not publish" in logs[0].read_text()
    (root / "uncommitted.txt").write_text("user data")
    result = subprocess.run([runner], cwd=root, env=env, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "Working tree has changes" in result.stderr
    assert len(list((root / "data/agent-runner").glob("*.log"))) == 1
