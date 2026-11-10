"""Read-only git operations on a bare mirror of the repository. The gate and reconciler use git
only as a data source (ancestry, trees, merge simulation). Nothing from the repository is ever
checked out or executed."""
import os
import subprocess

SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
        "-c", "core.fsmonitor=false", "-c", "safe.directory=*"]


class GitError(RuntimeError):
    pass


class Mirror:
    def __init__(self, path):
        self.path = path

    @classmethod
    def ensure(cls, repo, path, refresh=True):
        env = cls._env()
        if not os.path.isdir(path):
            url = f"https://github.com/{repo}.git"
            p = subprocess.run(["git", *SAFE, "clone", "--quiet", "--mirror", url, path],
                               capture_output=True, text=True, env=env, timeout=600)
            if p.returncode != 0:
                raise GitError(f"clone failed: {p.stderr[-300:]}")
        elif refresh:
            p = subprocess.run(["git", *SAFE, "-C", path, "remote", "update", "--prune"],
                               capture_output=True, text=True, env=env, timeout=600)
            if p.returncode != 0:
                raise GitError(f"fetch failed: {p.stderr[-300:]}")
        return cls(path)

    @staticmethod
    def _env():
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_ASKPASS": "/bin/false"})
        return env

    def run(self, *args, check=True):
        p = subprocess.run(["git", *SAFE, "-C", self.path, *args], capture_output=True,
                           text=True, env=self._env(), timeout=300)
        if check and p.returncode != 0:
            raise GitError(f"git {' '.join(args)}: {p.stderr.strip()[-300:]}")
        return p

    def fetch_sha(self, sha):
        if self.run("cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0:
            return
        self.run("fetch", "--quiet", "origin", sha, check=False)
        self.run("cat-file", "-e", f"{sha}^{{commit}}")

    def tree(self, sha):
        return self.run("rev-parse", f"{sha}^{{tree}}").stdout.strip()

    def parents(self, sha):
        out = self.run("rev-list", "--parents", "-n", "1", sha).stdout.split()
        return out[1:]

    def is_ancestor(self, a, b):
        return self.run("merge-base", "--is-ancestor", a, b, check=False).returncode == 0

    def merge_base(self, a, b):
        return self.run("merge-base", a, b).stdout.strip()

    def first_parent_range(self, base, head):
        """Commits on head's first-parent chain after base (oldest first), with parents."""
        out = self.run("rev-list", "--first-parent", "--parents", "--reverse",
                       f"{base}..{head}").stdout.splitlines()
        return [(l.split()[0], l.split()[1:]) for l in out if l.strip()]

    def clean_merge_tree(self, p1, p2):
        """Tree GitHub would produce for a conflict-free merge, or None if it conflicts."""
        p = self.run("merge-tree", "--write-tree", "--no-messages", p1, p2, check=False)
        if p.returncode != 0:
            return None
        return p.stdout.split()[0]
