
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
    Find trusted package names that closely resemble
    the supplied package name.
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

        if similarity >= threshold:
            suspicious_matches.append({
                "package": package_name,
                "similar_to": trusted_name,
                "similarity": round(similarity, 2)
            })

    suspicious_matches.sort(
        key=lambda item: item["similarity"],
        reverse=True
    )

    return suspicious_matches
