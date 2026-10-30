
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




from trustlayer.name_analyzer import (
    are_keyboard_neighbors,
    get_typo_reasons
)


def test_vertical_keyboard_neighbor():
    assert are_keyboard_neighbors("q", "a")


def test_diagonal_keyboard_neighbor():
    assert are_keyboard_neighbors("w", "a")


def test_horizontal_keyboard_neighbor():
    assert are_keyboard_neighbors("e", "w")


def test_character_insertion():
    assert "single_character_insertion" in get_typo_reasons(
        "requestss", "requests"
    )


def test_character_deletion():
    assert "single_character_deletion" in get_typo_reasons(
        "reqests", "requests"
    )


def test_adjacent_character_transposition():
    assert "adjacent_character_transposition" in get_typo_reasons(
        "requets s".replace(" ", ""), "requests"
    )


def test_integrated_insertion_detection():
    results = find_suspicious_names(
        "requestss",
        TRUSTED_PACKAGES
    )

    assert any(
        item["similar_to"] == "requests"
        and "single_character_insertion" in item["reasons"]
        for item in results
    )
