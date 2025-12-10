import tempfile
from pathlib import Path
from unittest import TestCase, main

from utils import ignore_requirements


STACKTRACES_REQUIREMENT = (
    "stacktraces @ git+https://github.com/trawick/stacktraces.py.git"
    "@4a06bb64aaf23c193b1590a661bcdce0d55b11e5"
)
ARTICLE_REQUIREMENT = (
    "emptyhammock_article @ git+https://github.com/trawick/emptyhammock-article.git"
    "@76859a6d456bffdcea0ccc754ba07b196af6e660"
)


class TestIgnoreRequirements(TestCase):

    @staticmethod
    def create_test_requirements(requirements):
        with open(requirements, "w", encoding="utf-8") as f:
            f.write("abc==1.0.0\n" + STACKTRACES_REQUIREMENT + "\n")
            f.write(ARTICLE_REQUIREMENT + "\n")

    def test_success(self):
        with tempfile.TemporaryDirectory() as dirname:
            original = Path(dirname) / "original.txt"
            edited = Path(dirname) / "edited.txt"
            self.create_test_requirements(original)
            all_packages, warnings = ignore_requirements(
                str(original),
                edited,
                ["abc", "stacktraces", "emptyhammock-article"]
            )
            self.assertEqual([
                "abc==1.0.0",
                ARTICLE_REQUIREMENT,
                STACKTRACES_REQUIREMENT,
            ], all_packages)
            self.assertEqual([], warnings)
            with open(edited, encoding="utf-8") as f:
                lines = f.readlines()
                self.assertEqual([], lines)

    def test_missing_ignored_requirement(self):
        with tempfile.TemporaryDirectory() as dirname:
            original = Path(dirname) / "original.txt"
            edited = Path(dirname) / "edited.txt"
            self.create_test_requirements(original)
            all_packages, warnings = ignore_requirements(
                str(original),
                edited,
                ["abc", "stacktraces.py"]
            )
            self.assertEqual([
                "should ignore for pip-audit, but not present:",
                "stacktraces.py",
            ], warnings)
            with open(edited, encoding="utf-8") as f:
                lines = f.readlines()
                self.assertEqual({
                    STACKTRACES_REQUIREMENT + "\n",
                    ARTICLE_REQUIREMENT + "\n",
                }, set(lines))


if __name__ == '__main__':
    main()
