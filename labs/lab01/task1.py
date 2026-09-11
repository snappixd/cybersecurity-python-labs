import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "SIEM@An4lysis",
    "easy123",
    "S0C@Analyst",
    "observer",
    "Threat@Hunt1ng",
    "viewer",
    "Incid3nt@Handle",
    "monitor",
    "Log@An4lysis",
    "watcher",
]

MIN_LENGTH = 9
REQUIRE_DIGITS = True
REQUIRE_UPPER = True
REQUIRE_SPECIAL = True

FORBIDDEN_PASSWORDS = ["easy123", "observer", "viewer", "monitor", "watcher", "admin"]


def simulate_password_reuse(passwords):
    reused_list = passwords.copy()

    count = 0
    while count < 3:
        random_index = random.randint(0, len(passwords) - 1)
        password_to_copy = passwords[random_index]
        reused_list.append(password_to_copy)
        count = count + 1

    return reused_list


def count_password_types(password):
    has_digit = False
    has_upper = False
    has_special = False

    for char in password:
        if char.isdigit():
            has_digit = True
        if char.isupper():
            has_upper = True
        if not char.isalnum():
            has_special = True

    return has_digit, has_upper, has_special


def classify_password(password, full_list):
    if password in FORBIDDEN_PASSWORDS:
        return "Заборонений"

    if len(password) < MIN_LENGTH:
        return "Заборонений"

    has_digit, has_upper, has_special = count_password_types(password)

    matched_count = 0
    total_checks = 0

    if REQUIRE_DIGITS:
        total_checks = total_checks + 1
        if has_digit:
            matched_count = matched_count + 1

    if REQUIRE_UPPER:
        total_checks = total_checks + 1
        if has_upper:
            matched_count = matched_count + 1

    if REQUIRE_SPECIAL:
        total_checks = total_checks + 1
        if has_special:
            matched_count = matched_count + 1

    meets_all_criteria = matched_count == total_checks

    if meets_all_criteria and len(password) >= MIN_LENGTH + 4:
        how_many_times = full_list.count(password)
        if how_many_times == 1:
            return "Дуже сильний"
        return "Сильний"

    if meets_all_criteria:
        return "Сильний"

    if matched_count > 0 and matched_count < total_checks:
        return "Середній"

    return "Слабкий"


def analyze_passwords(passwords):
    results = []
    for password in passwords:
        level = classify_password(password, passwords)
        results.append((password, level))
    return results


def print_results_table(results):
    print(f"{'Пароль':<20} {'Рівень надійності':<20}")
    print("-" * 40)
    for password, level in results:
        print(f"{password:<20} {level:<20}")


def main():
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("-" * 60)
    print("Завдання 1: Аналізатор надійності паролів\n")

    passwords_with_reuse = simulate_password_reuse(PASSWORDS)
    print("Список паролів після імітації повторного використання:")
    print(passwords_with_reuse)
    print()

    results = analyze_passwords(passwords_with_reuse)
    print_results_table(results)


if __name__ == "__main__":
    main()
