
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
    and keyboard-neighbor signals.
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

        keyboard_typo = has_keyboard_neighbor_typo(
            package_name,
            trusted_name
        )

        reasons = []

        if similarity >= threshold:
            reasons.append("high_name_similarity")

        if keyboard_typo:
            reasons.append("keyboard_neighbor_substitution")

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



def has_keyboard_neighbor_typo(name1: str, name2: str) -> bool:
    """
    Check whether two package names differ by
    one adjacent keyboard character.
    """

    keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    name1 = normalize_name(name1)
    name2 = normalize_name(name2)

    if len(name1) != len(name2):
        return False

    differences = 0

    for char1, char2 in zip(name1, name2):
        if char1 == char2:
            continue

        differences += 1

        if differences > 1:
            return False

        neighbors = set()

        for row in keyboard_rows:
            if char1 in row:
                index = row.index(char1)

                if index > 0:
                    neighbors.add(row[index - 1])

                if index < len(row) - 1:
                    neighbors.add(row[index + 1])

        if char2 not in neighbors:
            return False

    return differences == 1



