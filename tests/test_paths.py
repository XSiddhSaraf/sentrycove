import pytest

from sentrycove.paths import normalize_match_path, path_matches


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/login", "/login"),
        ("/LOGIN", "/login"),
        ("/login/", "/login"),
        ("//login", "/login"),
        ("/lo%67in", "/login"),
        ("/a/../login", "/login"),
        ("/a/./b/../../login", "/login"),
        ("/..%2f..%2flogin", "/login"),
        ("/a\\..\\login", "/login"),
        ("/../../login", "/login"),
        ("/", "/"),
        ("", "/"),
        ("/%252e%252e/login", "/%2e%2e/login"),  # decoded once only, as servers do
    ],
)
def test_normalize_match_path(raw, expected):
    assert normalize_match_path(raw) == expected


def test_path_matches_globs_and_prefixes():
    assert path_matches("/api/users/7", ["/api/*"])
    assert path_matches("/api", ["/api/*"])  # "/api/" normalises to "/api"
    assert not path_matches("/apix", ["/api/*"])
    assert path_matches("/checkout/pay", ["/checkout*"])
    assert path_matches("/login", ["/Login/"])  # patterns are normalised too
    assert path_matches("/anything", ["*"])
    assert not path_matches("/other", ["/login", "/signup"])
