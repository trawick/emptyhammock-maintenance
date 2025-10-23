import re
from pathlib import Path
from typing import List, Tuple


def ignore_requirements(
    original_requirements: str,
    edited_requirements: Path,
    ignored_packages: List[str],
) -> Tuple[List[str], List[str]]:
    with open(original_requirements, encoding="utf-8") as f:
        original_packages = f.readlines()
    successfully_ignored = set()
    all_packages = set()
    warnings = []
    with open(
        edited_requirements, "w", encoding="utf-8"
    ) as edited_requirements_file:
        for package_spec in original_packages:
            package_spec = package_spec.strip()
            all_packages.add(package_spec)
            m = re.match(r"^([^= ]+)([= ]).*", package_spec)
            if m:
                package_name = m.group(1)
                if package_name in ignored_packages:
                    successfully_ignored.add(package_name)
                else:
                    print(package_spec, end="", file=edited_requirements_file)
            else:
                warnings.append(f"Cannot understand {package_spec}")

    # Warn about any ignored packages which weren't found.
    ignored_packages_set = set(ignored_packages)
    if successfully_ignored != ignored_packages_set:
        warnings.append("should ignore for pip-audit, but not present:")
        for package_name in sorted(ignored_packages_set - successfully_ignored):
            warnings.append(package_name)

    return list(sorted(all_packages)), warnings
