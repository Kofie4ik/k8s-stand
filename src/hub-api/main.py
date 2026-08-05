"""
Бэкенд хаба pivasik.

Запуск:
    uvicorn main:app --host 0.0.0.0 --port 8000

Настройки берутся из переменных окружения — в кластере они приедут
из ConfigMap и Secret, локально их можно выставить в оболочке.
"""

import os
import time
import hmac
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Настройки
# ─────────────────────────────────────────────────────────────────────────────

DATABASE_URL   = os.environ.get("DATABASE_URL", "postgresql://postgres@/hub")
PROM_URL       = os.environ.get("PROM_URL", "http://prometheus-operated.monitoring:9090")
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
CLUSTER_TOKEN  = os.environ.get("CLUSTER_TOKEN", "")

SESSION_TTL    = int(os.environ.get("SESSION_TTL", 12 * 3600))   # 12 часов
COOKIE_NAME    = "hub_session"
# По HTTPS cookie должна ходить только с флагом Secure. Локально по http его
# приходится снимать, иначе браузер её просто не сохранит.
COOKIE_SECURE  = os.environ.get("COOKIE_SECURE", "1") == "1"

if not SESSION_SECRET:
    # Без секрета подпись сессии подделывается кем угодно. Лучше не стартовать
    # вовсе, чем молча работать с дырой.
    raise RuntimeError("SESSION_SECRET не задан")

hasher = PasswordHasher()
signer = URLSafeTimedSerializer(SESSION_SECRET, salt="hub-session")
pool: Optional[ConnectionPool] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Пул соединений живёт столько же, сколько процесс.

    Открывать соединение на каждый запрос дорого: рукопожатие с PostgreSQL
    занимает больше времени, чем сам запрос за новостями. Пул держит несколько
    готовых соединений и раздаёт их по кругу.
    """
    global pool
    # open=False + пустой check: если база ещё не поднялась, приложение всё равно
    # стартует и честно ответит на /readyz, что не готово. Падать при старте
    # нельзя — под уйдёт в CrashLoopBackOff и не даст себя диагностировать.
    pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=8, open=False,
                          kwargs={"row_factory": dict_row})
    pool.open(wait=False)
    yield
    pool.close()


app = FastAPI(title="hub-api", docs_url="/api/docs", openapi_url="/api/openapi.json",
              lifespan=lifespan)


# ─────────────────────────────────────────────────────────────────────────────
# Сессии
# ─────────────────────────────────────────────────────────────────────────────

class User(BaseModel):
    login: str
    role: str


GUEST = User(login="", role="guest")


def current_user(hub_session: Optional[str] = Cookie(default=None)) -> User:
    """Кто пришёл. Без действительной cookie — гость, это не ошибка.

    Сессия — не случайная строка в базе, а подписанные данные в самой cookie.
    Подделать её нельзя (подпись не сойдётся), а сервер не хранит ничего.
    Обратная сторона: досрочно погасить чужую сессию невозможно — она просто
    протухнет через SESSION_TTL.
    """
    if not hub_session:
        return GUEST
    try:
        data = signer.loads(hub_session, max_age=SESSION_TTL)
    except (BadSignature, SignatureExpired):
        return GUEST
    return User(login=data.get("login", ""), role=data.get("role", "reader"))


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="нужны права администратора")
    return user


# ── Ограничение попыток входа ────────────────────────────────────────────────
# Без него пароль подбирается перебором: сеть быстрее человека в миллионы раз.
# Счётчик в памяти процесса, при нескольких репликах у каждой свой — для стенда
# достаточно, для интернета нужен общий счётчик (Redis) или ограничение в traefik.
LOGIN_LIMIT, LOGIN_WINDOW = 5, 60
_attempts: dict[str, list[float]] = {}


def too_many_attempts(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    _attempts[ip] = hits
    return len(hits) >= LOGIN_LIMIT


def note_attempt(ip: str) -> None:
    _attempts.setdefault(ip, []).append(time.time())


# ─────────────────────────────────────────────────────────────────────────────
# Что принимаем и что отдаём
# ─────────────────────────────────────────────────────────────────────────────

class LoginIn(BaseModel):
    login: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class NewsIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=4000)


class NewsOut(BaseModel):
    id: int
    title: str
    body: str
    source: str
    author: Optional[str]
    created_at: str


# ─────────────────────────────────────────────────────────────────────────────
# Лента
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/news", response_model=list[NewsOut])
def list_news(limit: int = 20):
    limit = max(1, min(limit, 100))
    with pool.connection() as conn:
        rows = conn.execute(
            """select id, title, body, source, author, created_at
                 from news
             order by created_at desc
                limit %s""",
            (limit,),
        ).fetchall()
    return [NewsOut(**r | {"created_at": r["created_at"].isoformat()}) for r in rows]


@app.post("/api/news", response_model=NewsOut, status_code=201)
def add_news(item: NewsIn,
             user: User = Depends(current_user),
             x_cluster_token: Optional[str] = Header(default=None)):
    """Писать может админ (по cookie) или сам кластер (по токену).

    Токен сравниваем через hmac.compare_digest, а не через ==. Обычное сравнение
    строк выходит из цикла на первом несовпавшем символе, и по времени ответа
    токен теоретически подбирается посимвольно. Здесь сравнение всегда занимает
    одинаковое время.
    """
    # Сравниваем в байтах: compare_digest не умеет строки с не-ASCII символами
    # и падает на них с TypeError. Заголовок присылает кто угодно и какой угодно,
    # так что кириллица в нём — обычное дело, а не исключительная ситуация.
    from_cluster = bool(
        CLUSTER_TOKEN and x_cluster_token
        and hmac.compare_digest(x_cluster_token.encode("utf-8"),
                                CLUSTER_TOKEN.encode("utf-8"))
    )
    if from_cluster:
        source, author = "system", "cluster"
    elif user.role == "admin":
        source, author = "manual", user.login
    else:
        raise HTTPException(status_code=403, detail="писать в ленту нельзя")

    with pool.connection() as conn:
        row = conn.execute(
            """insert into news (title, body, source, author)
                    values (%s, %s, %s, %s)
                 returning id, title, body, source, author, created_at""",
            (item.title, item.body, source, author),
        ).fetchone()
    return NewsOut(**row | {"created_at": row["created_at"].isoformat()})


# ─────────────────────────────────────────────────────────────────────────────
# Вход
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/login")
def login(data: LoginIn, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    if too_many_attempts(ip):
        raise HTTPException(status_code=429, detail="слишком много попыток, подожди минуту")

    with pool.connection() as conn:
        row = conn.execute(
            "select login, pass_hash, role from users where login = %s", (data.login,)
        ).fetchone()

    # Отвечаем одинаково и на несуществующий логин, и на неверный пароль:
    # иначе по тексту ошибки перебираются существующие учётки.
    if not row:
        note_attempt(ip)
        # Хешируем вхолостую, чтобы ответ на несуществующий логин занимал столько
        # же времени, сколько на существующий — иначе логины видны по секундомеру.
        hasher.hash(data.password)
        raise HTTPException(status_code=401, detail="неверный логин или пароль")

    try:
        hasher.verify(row["pass_hash"], data.password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        note_attempt(ip)
        raise HTTPException(status_code=401, detail="неверный логин или пароль")

    token = signer.dumps({"login": row["login"], "role": row["role"]})
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=SESSION_TTL,
        httponly=True,      # JavaScript страницы cookie не увидит — защита от кражи при XSS
        secure=COOKIE_SECURE,
        samesite="lax",     # чужой сайт не дёрнет наши ручки от твоего имени
        path="/",
    )
    return {"login": row["login"], "role": row["role"]}


@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/me", response_model=User)
def me(user: User = Depends(current_user)):
    return user


# ─────────────────────────────────────────────────────────────────────────────
# Метрики кластера
# ─────────────────────────────────────────────────────────────────────────────

# Готовые запросы к Prometheus. Метрики стандартные, их поставляет node-exporter
# из стека kube-prometheus (см. заметку 20).
PROMQL = {
    "cpu_total": 'count(node_cpu_seconds_total{mode="idle"})',
    "cpu_used":  'sum(rate(node_cpu_seconds_total{mode!="idle"}[5m]))',
    "ram_total": "sum(node_memory_MemTotal_bytes)",
    "ram_used":  "sum(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)",
}


async def prom(client: httpx.AsyncClient, query: str) -> float:
    r = await client.get(f"{PROM_URL}/api/v1/query", params={"query": query})
    r.raise_for_status()
    result = r.json()["data"]["result"]
    if not result:
        raise ValueError(f"Prometheus ничего не вернул на запрос: {query}")
    return float(result[0]["value"][1])


@app.get("/api/metrics")
async def metrics():
    """Отдаёт браузеру два числа вместо доступа к Prometheus.

    Так Prometheus остаётся невидимым снаружи, а страница получает ровно то,
    что ей нужно нарисовать.
    """
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            cpu_total = await prom(client, PROMQL["cpu_total"])
            cpu_used  = await prom(client, PROMQL["cpu_used"])
            ram_total = await prom(client, PROMQL["ram_total"])
            ram_used  = await prom(client, PROMQL["ram_used"])
    except Exception as e:
        # 503, а не 500: это не поломка хаба, а недоступность соседа.
        # Страница по такому ответу сама переходит на демо-числа.
        raise HTTPException(status_code=503, detail=f"Prometheus недоступен: {e}")

    gb = 1024 ** 3
    return {
        "cpu": {"pct": round(cpu_used / cpu_total * 100, 1),
                "used": f"{cpu_used:.2f}", "total": int(cpu_total)},
        "ram": {"pct": round(ram_used / ram_total * 100, 1),
                "used": f"{ram_used / gb:.1f}", "total": f"{ram_total / gb:.1f}"},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Пробы
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    """Жив ли процесс. Базу здесь НЕ трогаем намеренно.

    Если проверять базу в liveness, её кратковременная недоступность превратится
    в бесконечный перезапуск совершенно здорового приложения.
    """
    return {"ok": True}


@app.get("/readyz")
def readyz():
    """Готов ли обслуживать запросы: процесс жив и база отвечает."""
    try:
        with pool.connection(timeout=3) as conn:
            conn.execute("select 1")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"база недоступна: {e}")
    return {"ok": True}
