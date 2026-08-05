# hub-api

Бэкенд хаба `pivasik`: лента новостей, вход, метрики кластера.
План и обоснования — заметка `26. Хаб с бэкендом — план`.

## Файлы

| файл | что это |
|---|---|
| `schema.sql` | таблицы `users` и `news`, накатывается один раз |
| `main.py` | само приложение (FastAPI) |
| `adduser.py` | завести пользователя или сменить ему пароль |
| `smoke.sh` | прогон всех ручек: что должно работать и что должно быть запрещено |
| `requirements.txt` | версии библиотек |

## Настройки — через окружение

| переменная | зачем | обязательна |
|---|---|---|
| `DATABASE_URL` | адрес PostgreSQL | да |
| `SESSION_SECRET` | ключ подписи сессий; без него приложение не стартует | да |
| `CLUSTER_TOKEN` | пароль кластера для записи в ленту | нет |
| `PROM_URL` | адрес Prometheus внутри кластера | нет |
| `SESSION_TTL` | срок жизни сессии в секундах, по умолчанию 12 часов | нет |
| `COOKIE_SECURE` | `1` — cookie только по HTTPS. Локально по http ставить `0` | нет |

`SESSION_SECRET` — длинная случайная строка. Взять можно так:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Менять его — значит разлогинить всех сразу:** старые подписи перестанут сходиться.

## Запуск на одной машине (для проверки)

```bash
pip install -r requirements.txt

createdb hub
psql -d hub -f schema.sql

export DATABASE_URL="postgresql://postgres@localhost/hub"
export SESSION_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
export CLUSTER_TOKEN="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export COOKIE_SECURE=0          # локально идём по http

python3 adduser.py viktor admin
uvicorn main:app --host 0.0.0.0 --port 8000
```

Живая документация со всеми ручками, которые можно нажать прямо в браузере:
`http://localhost:8000/api/docs`.

Проверить, что всё цело: `bash smoke.sh`.

## Ручки

| метод | путь | кто может |
|---|---|---|
| `GET`  | `/api/news` | все |
| `POST` | `/api/login` | все |
| `POST` | `/api/logout` | все |
| `GET`  | `/api/me` | все |
| `POST` | `/api/news` | админ по cookie **или** кластер по заголовку `X-Cluster-Token` |
| `GET`  | `/api/metrics` | все |
| `GET`  | `/healthz` | проба живости — базу намеренно не трогает |
| `GET`  | `/readyz` | проба готовности — проверяет коннект к базе |

## Как кластер пишет в ленту

```bash
curl -X POST https://pivasik.org/api/news \
  -H "Content-Type: application/json" \
  -H "X-Cluster-Token: $CLUSTER_TOKEN" \
  -d '{"title":"Argo CD синхронизировал 14 приложений","body":"Расхождений с git нет."}'
```

Запись получит `source: system` и автора `cluster` — на странице это ярлык «система».
