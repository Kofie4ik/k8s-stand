-- Схема хаба. Накатывается один раз, повторный запуск безопасен.
--
--   psql -h <хост> -U <пользователь> -d hub -f schema.sql

-- ── Пользователи ────────────────────────────────────────────────────────────
-- pass_hash — argon2-хеш, а не пароль. Хеш считается только в одну сторону:
-- при входе мы хешируем введённое и сравниваем хеши. Даже полный доступ к базе
-- (например, через Adminer) не даёт паролей.
create table if not exists users (
  id         serial      primary key,
  login      text        not null unique,
  pass_hash  text        not null,
  role       text        not null default 'reader'
             check (role in ('reader', 'admin')),
  -- Поколение сессий. Номер кладётся в cookie при входе и сверяется при каждом
  -- запросе. Смена пароля или сброс входов увеличивают его — и все выданные
  -- ранее cookie перестают сходиться. Отдельной таблицы сессий не нужно.
  sess_ver   integer     not null default 1,
  created_at timestamptz not null default now()
);

-- ── Новости ─────────────────────────────────────────────────────────────────
-- source отделяет записи кластера от написанных человеком: на странице это
-- ярлыки «система» и «вручную».
create table if not exists news (
  id         serial      primary key,
  title      text        not null check (length(title) between 1 and 200),
  body       text        not null check (length(body)  between 1 and 4000),
  source     text        not null default 'manual'
             check (source in ('manual', 'system')),
  author     text,
  created_at timestamptz not null default now()
);

-- Лента всегда запрашивается «свежие сверху», поэтому индекс по убыванию даты.
-- Без него на каждый запрос читалась бы вся таблица целиком.
create index if not exists news_created_idx on news (created_at desc);
