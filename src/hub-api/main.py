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
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
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
# Ограничение размера запроса
# ─────────────────────────────────────────────────────────────────────────────
# Проверки длины полей срабатывают уже после разбора тела: к тому моменту
# память съедена. Отсекаем по заголовку, не читая тело вовсе.
# Второй рубеж — traefik: он ловит и запросы без Content-Length, а этот
# код такой запрос пропустит.

MAX_BODY = 32 * 1024


@app.middleware("http")
async def limit_body(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY:
        return JSONResponse({"detail": "запрос слишком большой"}, status_code=413)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def short_validation_error(request: Request, exc: RequestValidationError):
    """FastAPI по умолчанию возвращает присланное значение обратно в тексте
    ошибки. На длинном вводе ответ весит столько же, сколько запрос."""
    return JSONResponse(
        {"detail": [{"loc": e.get("loc"), "msg": e.get("msg")} for e in exc.errors()]},
        status_code=422,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Сессии
# ─────────────────────────────────────────────────────────────────────────────

class User(BaseModel):
    login: str
    role: str


GUEST = User(login="", role="guest")


def issue_session(response: Response, login: str, ver: int) -> None:
    """Выдать cookie. Единственное место, где она создаётся — и при входе,
    и после смены пароля, чтобы тот, кто меняет, не выкинул сам себя."""
    token = signer.dumps({"login": login, "ver": ver})
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=SESSION_TTL,
        httponly=True,      # JavaScript страницы cookie не увидит — защита от кражи при XSS
        secure=COOKIE_SECURE,
        samesite="lax",     # чужой сайт не дёрнет наши ручки от твоего имени
        path="/",
    )


def bump_session_version(conn, login: str) -> int:
    """Погасить все выданные cookie этого пользователя.

    ЕДИНСТВЕННОЕ место, где счётчик двигается. Любая правка учётки — смена
    пароля, смена роли, удаление — обязана проходить здесь. Если завести
    второй путь, отзыв однажды тихо перестанет работать: ошибки не будет,
    просто старые cookie останутся живыми.
    """
    row = conn.execute(
        "update users set sess_ver = sess_ver + 1 where login = %s returning sess_ver",
        (login,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="пользователь не найден")
    return row["sess_ver"]


def current_user(hub_session: Optional[str] = Cookie(default=None)) -> User:
    """Кто пришёл. Без действительной cookie — гость, это не ошибка.

    Подпись говорит только о том, что cookie не подделали. Всё остальное
    берём из базы: номер поколения сессии и роль. Поэтому смена пароля гасит
    все входы сразу, удаление пользователя действует немедленно, а понижение
    роли не ждёт, пока протухнет cookie с написанным в ней 'admin'.

    Цена — запрос к базе на каждый вызов. Для одной реплики это доли
    миллисекунды по первичному ключу; при росте сюда добавится кеш на
    несколько секунд, и вместе с ним — окно, в котором отозванная cookie ещё
    жива. Пока не нужно.
    """
    if not hub_session:
        return GUEST
    try:
        data = signer.loads(hub_session, max_age=SESSION_TTL)
    except (BadSignature, SignatureExpired):
        return GUEST

    login, ver = data.get("login", ""), data.get("ver")
    if not login or ver is None:
        return GUEST        # cookie старого образца, без поколения

    try:
        with pool.connection() as conn:
            row = conn.execute(
                "select role, sess_ver from users where login = %s", (login,)
            ).fetchone()
    except Exception:
        # База недоступна — считаем гостем, а не верим cookie на слово.
        # Отказ в правах при аварии лучше, чем выданные права без проверки.
        return GUEST

    if not row or row["sess_ver"] != ver:
        return GUEST
    return User(login=login, role=row["role"])


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


class PasswordIn(BaseModel):
    old_password: str = Field(min_length=1, max_length=200)
    # Нижняя граница у нового пароля, а не у старого: старый нужно принять
    # любым, каким он был заведён, иначе человек не сможет его сменить.
    new_password: str = Field(min_length=10, max_length=200)


class RevokeIn(BaseModel):
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
            "select login, pass_hash, role, sess_ver from users where login = %s",
            (data.login,),
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

    issue_session(response, row["login"], row["sess_ver"])
    return {"login": row["login"], "role": row["role"]}


@app.post("/api/logout")
def logout(response: Response):
    """Выход на этом устройстве: просто убираем cookie у себя.

    Остальные её копии, если они есть, продолжают работать — для них нужен
    отзыв, /api/sessions/revoke.
    """
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.post("/api/password")
def change_password(data: PasswordIn, request: Request, response: Response,
                    user: User = Depends(current_user)):
    """Смена пароля. Старый спрашиваем обязательно: cookie может быть краденой,
    и без этой проверки вор менял бы пароль хозяину.
    """
    if user.role == "guest":
        raise HTTPException(status_code=401, detail="нужно войти")

    ip = request.client.host if request.client else "?"
    if too_many_attempts(ip):
        raise HTTPException(status_code=429, detail="слишком много попыток, подожди минуту")

    if data.new_password == data.old_password:
        raise HTTPException(status_code=400, detail="новый пароль совпадает со старым")

    with pool.connection() as conn:
        row = conn.execute(
            "select pass_hash from users where login = %s", (user.login,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="нужно войти")
        try:
            hasher.verify(row["pass_hash"], data.old_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            note_attempt(ip)
            raise HTTPException(status_code=401, detail="старый пароль не подходит")

        conn.execute(
            "update users set pass_hash = %s where login = %s",
            (hasher.hash(data.new_password), user.login),
        )
        ver = bump_session_version(conn, user.login)

    # Пароль и счётчик меняются в одной транзакции: если что-то упадёт между
    # ними, не выйдет ни пароля без отзыва, ни отзыва без пароля.
    issue_session(response, user.login, ver)
    return {"ok": True, "detail": "пароль изменён, остальные входы сброшены"}


@app.post("/api/sessions/revoke")
def revoke_sessions(data: RevokeIn, request: Request, response: Response,
                    user: User = Depends(current_user)):
    """Выйти на всех остальных устройствах.

    Пароль спрашиваем не из вредности: без него укравший cookie одним нажатием
    выкидывает хозяина и остаётся один. Опасное действие подтверждается тем,
    чего у вора нет.
    """
    if user.role == "guest":
        raise HTTPException(status_code=401, detail="нужно войти")

    ip = request.client.host if request.client else "?"
    if too_many_attempts(ip):
        raise HTTPException(status_code=429, detail="слишком много попыток, подожди минуту")

    with pool.connection() as conn:
        row = conn.execute(
            "select pass_hash from users where login = %s", (user.login,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="нужно войти")
        try:
            hasher.verify(row["pass_hash"], data.password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            note_attempt(ip)
            raise HTTPException(status_code=401, detail="пароль не подходит")
        ver = bump_session_version(conn, user.login)

    issue_session(response, user.login, ver)
    return {"ok": True, "detail": "остальные входы сброшены"}


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
