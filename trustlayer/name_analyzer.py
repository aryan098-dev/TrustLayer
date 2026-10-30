
from rapidfuzz import fuzz


def normalize_name(package_name: str) -> str:
    """
    Normalize a package name for comparison.
    """
    return package_name.lower().strip()


def calculate_similarity(name1: str, name2: str) -> float:
    """
    Calculate similarity between two package names.
    Returns a score between 0 and 100.
    """
    name1 = normalize_name(name1)
    name2 = normalize_name(name2)

    return fuzz.ratio(name1, name2)




def find_suspicious_names(
    package_name: str,
    trusted_packages: list[str],
    threshold: float = 80
) -> list[dict]:
    """
    Detect suspicious package names using similarity
    and multiple typo-detection signals.
    """

    suspicious_matches = []

    package_name = normalize_name(package_name)

    for trusted_name in trusted_packages:
        trusted_name = normalize_name(trusted_name)

        if package_name == trusted_name:
            continue

        similarity = calculate_similarity(
            package_name,
            trusted_name
        )

        reasons = []

        if similarity >= threshold:
            reasons.append("high_name_similarity")

        reasons.extend(
            get_typo_reasons(package_name, trusted_name)
        )

        if reasons:
            suspicious_matches.append({
                "package": package_name,
                "similar_to": trusted_name,
                "similarity": round(similarity, 2),
                "reasons": reasons
            })

    suspicious_matches.sort(
        key=lambda item: item["similarity"],
        reverse=True
    )

    return suspicious_matches





# Approximate staggered QWERTY keyboard coordinates.
KEY_COORDINATES = {}

KEYBOARD_ROWS = [
    ("qwertyuiop", 0.0),
    ("asdfghjkl", 0.25),
    ("zxcvbnm", 0.75)
]

for row, offset in KEYBOARD_ROWS:
    for index, character in enumerate(row):
        KEY_COORDINATES[character] = (index + offset, KEYBOARD_ROWS.index((row, offset)))


def are_keyboard_neighbors(char1: str, char2: str) -> bool:
    """Check horizontal, vertical, and diagonal keyboard adjacency."""

    if char1 not in KEY_COORDINATES or char2 not in KEY_COORDINATES:
        return False

    x1, y1 = KEY_COORDINATES[char1]
    x2, y2 = KEY_COORDINATES[char2]

    dx = abs(x1 - x2)
    dy = abs(y1 - y2)

    return (
        dx <= 1.0
        and dy <= 1
        and (dx > 0 or dy > 0)
    )


def has_keyboard_neighbor_typo(name1: str, name2: str) -> bool:
    """Detect exactly one adjacent-key substitution."""

    name1 = normalize_name(name1)
    name2 = normalize_name(name2)

    if len(name1) != len(name2):
        return False

    differences = []

    for char1, char2 in zip(name1, name2):
        if char1 != char2:
            differences.append((char1, char2))

    if len(differences) != 1:
        return False

    char1, char2 = differences[0]

    return are_keyboard_neighbors(char1, char2)


def get_typo_reasons(candidate: str, trusted: str) -> list[str]:
    """Identify common single-edit package-name typo patterns."""

    candidate = normalize_name(candidate)
    trusted = normalize_name(trusted)

    reasons = []

    if has_keyboard_neighbor_typo(candidate, trusted):
        reasons.append("keyboard_neighbor_substitution")

    # Detect one extra character in the candidate.
    if len(candidate) == len(trusted) + 1:
        i = j = 0
        skipped = False

        while i < len(candidate) and j < len(trusted):
            if candidate[i] == trusted[j]:
                i += 1
                j += 1
            elif not skipped:
                skipped = True
                i += 1
            else:
                break

        if i == len(candidate) - 1 or (
            i == len(candidate) and j == len(trusted)
        ):
            reasons.append("single_character_insertion")

    # Detect one missing character in the candidate.
    elif len(trusted) == len(candidate) + 1:
        i = j = 0
        skipped = False

        while i < len(candidate) and j < len(trusted):
            if candidate[i] == trusted[j]:
                i += 1
                j += 1
            elif not skipped:
                skipped = True
                j += 1
            else:
                break

        if j == len(trusted) - 1 or (
            i == len(candidate) and j == len(trusted)
        ):
            reasons.append("single_character_deletion")

    # Detect two neighboring characters swapped.
    elif len(candidate) == len(trusted):
        differences = [
            i for i, (a, b) in enumerate(zip(candidate, trusted))
            if a != b
        ]

        if len(differences) == 2:
            first, second = differences

            if (
                second == first + 1
                and candidate[first] == trusted[second]
                and candidate[second] == trusted[first]
            ):
                reasons.append("adjacent_character_transposition")

    return reasons
