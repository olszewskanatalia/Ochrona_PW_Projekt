import math
import os
import uuid
import re

from passlib.context import CryptContext

pepper = "gIIzYM9u@hhs7WDM/xNL24r6HUjAmSJhjW1YhWj7"

def generate_gguid():
    return str(uuid.uuid4())


def hash_password(password):
    salt = os.urandom(16)
    password_with_salt_and_pepper = password.encode('utf-8') + salt + pepper.encode('utf-8')
    context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
    hashed_password = context.hash(password_with_salt_and_pepper)
    return hashed_password, salt


def calculate_password_entropy(data: str) -> float:
    count = [0] * 256
    dataSize = len(data)
    for char in data:
        b = ord(char)
        count[b] = count[b] + 1
    entropy = 0
    for b in range(256):
        if count[b] / dataSize > 0:
            entropy = entropy + (count[b] / dataSize) * math.log(count[b] / dataSize, 2)
    return -entropy


def check_criteria(password):
    is_at_least_eight_characters = len(password) >= 9
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char.isascii() and not char.isalnum() for char in password)
    return has_lowercase and has_uppercase and has_digit and has_special and is_at_least_eight_characters


def evaluate_password_strength(password):
    meets_all_criteria = check_criteria(password)
    entropy = calculate_password_entropy(password)

    if meets_all_criteria and entropy > 3:
        return 1
    elif meets_all_criteria:
        return 0
    else:
        return -1


def is_password_correct(password, hash, salt):
    context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
    password_with_salt_and_pepper = password.encode('utf-8') + salt + pepper.encode('utf-8')
    return context.verify(password_with_salt_and_pepper, hash)


def is_valid_email(email):
    email_regex = re.compile(r'^\S+@\S+\.\S+$')
    return bool(email_regex.match(email))


def create_database(cursor):
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS user (
            user_id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            public_id TEXT UNIQUE
        )
    ''')

    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS note (
            note_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            type TEXT CHECK (type IN ('PRIVATE', 'PROTECTED', 'PUBLIC')) NOT NULL,
            password TEXT CHECK (password IS NULL OR type IN ('PROTECTED')),
            salt TEXT,
            creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            content TEXT NOT NULL,
            owner_id TEXT REFERENCES user(user_id) NOT NULL,
            owner_name TEXT REFERENCES user(name) NOT NULL
        )
    ''')

    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS shared_note (
            shared_note_id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id TEXT REFERENCES note(note_id) NOT NULL,
            user_id TEXT REFERENCES user(user_id) NOT NULL,
            UNIQUE (note_id, user_id)
        )
    ''')
    
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS log_login (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            login_failed_attempts INT NOT NULL,
            user_id TEXT REFERENCES user(user_id) NOT NULL,
            accout_status TEXT NOT NULL,
            UNIQUE (user_id)
        )
    ''')


def initial_insert(cursor):
    cursor.execute("DROP TABLE IF EXISTS user;")
    cursor.execute("DROP TABLE IF EXISTS note;")
    cursor.execute("DROP TABLE IF EXISTS shared_note;")
    
    create_database(cursor)

    # Inserting data for user 'ala'
    ala_user_id = generate_gguid()
    ala_public_id = generate_gguid()
    ala_pass, ala_salt = hash_password('AlamaKota123!')

    cursor.execute("""
        INSERT INTO user (user_id, name, email, password, salt, public_id)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (ala_user_id, 'ala', 'ala@example.com', ala_pass, ala_salt, ala_public_id)
    )
    
    cursor.execute("""
        INSERT INTO log_login (login_failed_attempts, user_id, accout_status)
        VALUES (?, ?, ?)""",
        (0, ala_user_id, 'ACTIVE')
    )


    ala_public_note_id = generate_gguid()
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (ala_public_note_id, 'Public Note Ala', 'PUBLIC', None, None, '<h1>Public content for Ala</h1>', 'ala', 'ala'))

    ala_protected_note_id = generate_gguid()
    ala_prot_pass, ala_prot_salt = hash_password('ProtectedAla22@')
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (ala_protected_note_id, 'Protected Note Ala', 'PROTECTED', ala_prot_pass, ala_prot_salt, 'Protected content for Ala', 'ala', 'ala'))

    ala_private_note_id = generate_gguid()
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (ala_private_note_id, 'Private Note Ala', 'PRIVATE', None, None, 'Private content for Ala', 'ala', 'ala'))


    # Inserting data for user 'bach'
    bach_user_id = generate_gguid()
    bach_public_id = generate_gguid()
    bach_pass, bach_salt = hash_password('TuBYLB@0bab!')

    cursor.execute("""
        INSERT INTO user (user_id, name, email, password, salt, public_id)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (bach_user_id, 'bach', 'bach@example.com', bach_pass, bach_salt, bach_public_id)
    )

    cursor.execute("""
        INSERT INTO log_login (login_failed_attempts, user_id, accout_status)
        VALUES (?, ?, ?)""",
        (0, bach_user_id, 'ACTIVE')
    )

    bach_public_note_id = generate_gguid()
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (bach_public_note_id, 'Public Note bach', 'PUBLIC', None, None, 'Public content for Bach', 'bach', 'bach'))

    bach_protected_note_id = generate_gguid()
    bach_prot_pass, bach_prot_salt = hash_password('ProtectedBach22@')
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (bach_protected_note_id, 'Protected Note Bach', 'PROTECTED', bach_prot_pass, bach_prot_salt, 'Protected content for Bach', 'bach', 'bach'))

    bach_private_note_id = generate_gguid()
    cursor.execute("""
        INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
        VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
    """, (bach_private_note_id, 'Private Note Bach', 'PRIVATE', None, None, 'Private content for Bach', 'bach', 'bach'))


    # Share bach's note with user 'ala'
    cursor.execute("""
        INSERT INTO shared_note (note_id, user_id)
        VALUES ((SELECT note_id FROM note WHERE title=? AND owner_id=(SELECT user_id FROM user WHERE name=?)),
                (SELECT user_id FROM user WHERE name=?))
    """, ('Private Note Bach', 'bach', 'ala'))