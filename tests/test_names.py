
from trustlayer.name_analyzer import (
    normalize_name,
    calculate_similarity,
    find_suspicious_names
)


TRUSTED_PACKAGES = [
    "requests",
    "numpy",
    "pandas",
    "django",
    "flask"
]


def test_normalize_name():
    assert normalize_name(" Requests ") == "requests"


def test_exact_match_similarity():
    assert calculate_similarity(
        "requests", "requests"
    ) == 100


def test_detect_lookalike():
    results = find_suspicious_names(
        "reqeusts",
        TRUSTED_PACKAGES
    )

    assert any(
        item["similar_to"] == "requests"
        for item in results
    )


def test_no_match_for_unrelated_name():
    results = find_suspicious_names(
        "completely-different",
        TRUSTED_PACKAGES
    )

    assert results == []



from trustlayer.name_analyzer import has_keyboard_neighbor_typo


def test_keyboard_neighbor_typo():
    assert has_keyboard_neighbor_typo(
        "flask", "flasj"
    )


def test_identical_names_are_not_typos():
    assert not has_keyboard_neighbor_typo(
        "requests", "requests"
    )


def test_unrelated_names_are_not_keyboard_typos():
    assert not has_keyboard_neighbor_typo(
        "requests", "numpy"
    )



def test_keyboard_detection_integrated():
    results = find_suspicious_names(
        "flasj",
        TRUSTED_PACKAGES
    )

    assert any(
        item["similar_to"] == "flask"
        and "keyboard_neighbor_substitution"
        in item["reasons"]
        for item in results
    )
