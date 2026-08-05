"""
Завести пользователя. Пароль спрашивается скрытым вводом и в историю
оболочки не попадает.

    DATABASE_URL=postgresql://... python3 adduser.py <логин> [admin|reader]

Повторный запуск с тем же логином меняет пароль и роль.
"""

import getpass
import os
import sys

import psycopg
from argon2 import PasswordHasher

login = sys.argv[1] if len(sys.argv) > 1 else input("логин: ").strip()
role = sys.argv[2] if len(sys.argv) > 2 else "admin"

if role not in ("admin", "reader"):
    sys.exit("роль бывает только admin или reader")

pw = getpass.getpass("пароль: ")
if pw != getpass.getpass("ещё раз: "):
    sys.exit("пароли не совпали")
if len(pw) < 8:
    sys.exit("пароль короче восьми знаков — не стоит")

# В базу уходит хеш. Сам пароль не сохраняется нигде и никогда.
pass_hash = PasswordHasher().hash(pw)

with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
    conn.execute(
        """insert into users (login, pass_hash, role) values (%s, %s, %s)
           on conflict (login) do update
                   set pass_hash = excluded.pass_hash,
                       role      = excluded.role""",
        (login, pass_hash, role),
    )

print(f"готово: {login} ({role})")
