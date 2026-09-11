import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 8
PERSONAL_SALT = "00012" 

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

USERS_TO_REGISTER = [
    ("admin_ivanenko", "S3cur3P@ssw0rd"),
    ("analyst_petrenko", "An4lyst!2024"),
    ("engineer_kovalchuk", "Eng1neer#Pass"),
    ("devops_shevchenko", "D3vOps@2024"),
    ("intern_melnyk", "Intern123!"),
    ("manager_boiko", "M@nager2024"),
    ("guest_tkachenko", "Gu3st#Pass"),
    ("auditor_bondar", "Aud1tor!Secure"),
    ("support_marchenko", "Supp0rt@2024"),
    ("root_lysenko", "Ro0t!P@ssword"),
]


class ValidationError(Exception):
    """Власний виняток: пароль не проходить мінімальні вимоги довжини."""


def log_event(func):
    def wrapper(username, password):
        try:
            success = func(username, password)
        except Exception:
            write_log_event(username, "failure")
            raise

        if success:
            write_log_event(username, "success")
        else:
            write_log_event(username, "failure")

        return success

    return wrapper


def write_log_event(username, result):
    now = datetime.now(timezone.utc)
    event = {
        "event": "login",
        "user": username,
        "result": result,
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "args": [],
        "kwargs": {},
    }

    try:
        os.makedirs(DATA_DIR, exist_ok=True)

        if os.path.exists(LOG_JSON_PATH):
            log_file = open(LOG_JSON_PATH, "r", encoding="utf-8")
            events = json.load(log_file)
            log_file.close()
        else:
            events = []

        events.append(event)

        log_file = open(LOG_JSON_PATH, "w", encoding="utf-8")
        json.dump(events, log_file, ensure_ascii=False, indent=2)
        log_file.close()
    except (FileNotFoundError, PermissionError, IOError) as error:
        print(f"Не вдалося записати лог: {error}")


def generate_hash(password, salt="00000"):
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль закороткий: мінімум {MIN_PASSWORD_LENGTH} символів")

    combined = password + salt
    hash_object = hashlib.md5(combined.encode("utf-8"))
    return hash_object.hexdigest()


def create_user(username, password):
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        csv_file = open(USERS_CSV_PATH, "w", newline="", encoding="utf-8")
        writer = csv.writer(csv_file)

        for username, password in users_list:
            try:
                username, hash_value = create_user(username, password)
                writer.writerow([username, hash_value])
            except ValidationError as error:
                print(f"Пропущено {username}: {error}")

        csv_file.close()
    except (PermissionError, IOError) as error:
        print(f"Помилка запису users.csv: {error}")


def load_users_db():
    users_db = []
    try:
        csv_file = open(USERS_CSV_PATH, "r", encoding="utf-8")
        reader = csv.reader(csv_file)
        for row in reader:
            if row:
                users_db.append((row[0], row[1]))
        csv_file.close()
    except FileNotFoundError as error:
        print(f"Файл бази користувачів не знайдено: {error}")
    return users_db


def print_users_db(users_db):
    print(f"{'Логін':<25} {'Хеш пароля':<35}")
    print("-" * 60)
    for username, hash_value in users_db:
        print(f"{username:<25} {hash_value:<35}")


@log_event
def login(username, password):
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    users_db = load_users_db()

    stored_hash = None
    for login_name, hash_value in users_db:
        if login_name == username:
            stored_hash = hash_value

    if stored_hash is None:
        return False

    try:
        candidate_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False

    return candidate_hash == stored_hash


def main():
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print("-" * 60)
    print("Завдання 3: Хешування, CSV-база та JSON-логування\n")

    print(f"Персональна сіль: {PERSONAL_SALT}")
    print("Алгоритм хешування: MD5\n")

    create_users(USERS_TO_REGISTER)
    users_db = load_users_db()
    print_users_db(users_db)
    print()

    print("Тест автентифікації:")
    test_cases = [
        ("admin_ivanenko", "S3cur3P@ssw0rd"),  # правильний пароль
        ("admin_ivanenko", "WrongPass123"),  # неправильний пароль
        ("nonexistent_user", "SomePass123"),  # неіснуючий користувач
    ]
    for username, password in test_cases:
        try:
            success = login(username, password)
            if success:
                print(f"  login('{username}') -> успішно")
            else:
                print(f"  login('{username}') -> невдало")
        except (ValueError, ValidationError) as error:
            print(f"  login('{username}') -> помилка: {error}")

    try:
        login("", "somepassword")
    except ValueError as error:
        print(f"\n  Очікувана помилка на порожній логін: {error}")


if __name__ == "__main__":
    main()
