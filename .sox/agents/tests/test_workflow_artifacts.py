import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import planning_agent  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def upload_blocks(workflow):
    """(artifact name, the `with:` block text) of every actions/upload-artifact step."""
    with open(os.path.join(ROOT, ".github", "workflows", workflow)) as f:
        text = f.read()
    out = []
    for m in re.finditer(r"uses: actions/upload-artifact@\S+.*\n((?:\s{8,}.*\n)+)", text):
        name = re.search(r"name: (\S+)", m.group(1))
        out.append((name.group(1) if name else None, m.group(1)))
    return out


class ContextArtifacts(unittest.TestCase):
    def test_dotfile_contexts_upload_hidden_files(self):
        # upload-artifact v4 silently drops dotfiles; the receiving job's dir_digest check then fails.
        hidden = [p for p in planning_agent.REPO_FILES if any(part.startswith(".") for part in p.split("/"))]
        self.assertTrue(hidden, "test assumes a dotfile in REPO_FILES")
        for workflow, artifact in (("sox-pm-agent.yml", "pm-context"), ("sox-techlead-agent.yml", "techlead-context")):
            blocks = [b for n, b in upload_blocks(workflow) if n == artifact]
            self.assertEqual(len(blocks), 1, workflow)
            self.assertRegex(blocks[0], r"include-hidden-files: true", workflow)


if __name__ == "__main__":
    unittest.main()
