import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "devsecops_lead": {
        "role": "devsecops",
        "clearance": 4,
        "department": "DevSecOps",
        "active": True,
    },
    "security_engineer": {
        "role": "security_engineer",
        "clearance": 3,
        "department": "Security Engineering",
        "active": True,
    },
    "automation_tech": {
        "role": "automation",
        "clearance": 2,
        "department": "Automation",
        "active": True,
    },
    "api_developer": {
        "role": "api_developer",
        "clearance": 2,
        "department": "API",
        "active": True,
    },
    "sandbox_env": {
        "role": "sandbox",
        "clearance": 1,
        "department": "Testing",
        "active": False,
    },
}

RESOURCES = [
    ("security_pipelines", 4),
    ("secure_coding_standards", 3),
    ("automation_scripts", 2),
    ("api_specifications", 2),
    ("threat_models", 4),
    ("testing_frameworks", 1),
    ("security_gates", 3),
    ("vulnerability_scans", 4),
    ("integration_tests", 2),
    ("mock_services", 1),
]

SECURITY_LEVELS = ("Sandbox", "Development", "Secure", "Production Critical")

BLOCKED_USERS = {"sandbox_env", "pipeline_breach", "automation_fail"}


def print_resources(resources, security_levels):
    print("Ресурси системи:")
    for name, level in resources:
        level_name = security_levels[level - 1]
        print(f"  {name:<25} -> рівень {level} ({level_name})")
    print()


def check_access(username, resource_level, users, blocked_users):
    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user = users[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= resource_level:
        return "ALLOW", None

    return "DENY", "Insufficient clearance"


def run_access_checks(users, resources, blocked_users):
    results = []
    for username in users:
        for resource_name, resource_level in resources:
            decision, reason = check_access(
                username, resource_level, users, blocked_users
            )
            results.append((username, resource_name, decision, reason))
    return results


def print_access_results(results):
    for username, resource_name, decision, reason in results:
        if reason:
            print(f"user={username} resource={resource_name} -> {decision} ({reason})")
        else:
            print(f"user={username} resource={resource_name} -> {decision}")


def main():
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("-" * 60)
    print("Завдання 2: Система контролю доступу\n")

    print_resources(RESOURCES, SECURITY_LEVELS)

    results = run_access_checks(USERS, RESOURCES, BLOCKED_USERS)
    print_access_results(results)


if __name__ == "__main__":
    main()
