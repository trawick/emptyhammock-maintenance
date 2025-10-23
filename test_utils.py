import tempfile
from pathlib import Path
from unittest import TestCase, main

from utils import ignore_requirements


class TestIgnoreRequirements(TestCase):
    @staticmethod
    def create_test_requirements(requirements):
        with open(requirements, "w", encoding="utf-8") as f:
            f.write(
                "abc==1.0.0\n"
                "stacktraces @ git+https://github.com/trawick/stacktraces.py."
                "git@4a06bb64aaf23c193b1590a661bcdce0d55b11e5\n",
            )

    def test_success(self):
        with tempfile.TemporaryDirectory() as dirname:
            original = Path(dirname) / "original.txt"
            edited = Path(dirname) / "edited.txt"
            self.create_test_requirements(original)
            all_packages, warnings = ignore_requirements(
                str(original),
                edited,
                ["abc", "stacktraces"]
            )
            self.assertEqual([
                "abc==1.0.0",
                "stacktraces @ git+https://github.com/trawick/stacktraces.py."
                "git@4a06bb64aaf23c193b1590a661bcdce0d55b11e5",
            ], all_packages)
            self.assertEqual([], warnings)

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


if __name__ == '__main__':
    main()
