import importlib.util
from pathlib import Path

import sentrycove

_SPEC = importlib.util.spec_from_file_location(
    "check_versions", Path(__file__).resolve().parent.parent / "scripts" / "check_versions.py"
)
check_versions = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(check_versions)


def test_all_packages_share_one_version():
    assert check_versions.check() == []
    assert set(check_versions.read_versions().values()) == {sentrycove.__version__}


def test_release_tag_must_match_the_version():
    assert check_versions.check(f"v{sentrycove.__version__}") == []
    assert check_versions.check("v99.0.0") != []
    assert check_versions.check(sentrycove.__version__) != []  # the tag needs its "v"
