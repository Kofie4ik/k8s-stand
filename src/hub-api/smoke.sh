#!/usr/bin/env bash
# Прогон всех ручек. Проверяет не только «работает», но и «запрещённое запрещено» —
# вторая половина важнее: сломанную функцию замечаешь сразу, дырку в правах — нет.
#
#   B=http://localhost:8000 ADMIN=viktor ADMIN_PW=... CLUSTER_TOKEN=... bash smoke.sh

set -u
# без UTF-8-локали bash считает длину строк в байтах, и колонки разъезжаются
export LC_ALL="${LC_ALL:-C.UTF-8}"
B="${B:-http://127.0.0.1:8000}"
ADMIN="${ADMIN:-viktor}"
ADMIN_PW="${ADMIN_PW:-verysecret123}"
CLUSTER_TOKEN="${CLUSTER_TOKEN:-cluster-token-12345}"
JAR="$(mktemp)"
ok=0; bad=0

# Ждём один из перечисленных кодов; всё остальное — провал.
# Список, а не одно число, нужен там, где годятся оба исхода: например
# «не пустило» — это и 401 (пароль не тот), и 429 (уже надоел попытками).
check() {
  local want="$1" name="$2"; shift 2
  local got; got=$("$@" -s -o /dev/null -w '%{http_code}')
  local pad=$(( 46 - ${#name} )); [ "$pad" -lt 1 ] && pad=1
  if [[ " $want " == *" $got "* ]]; then
    printf '  \033[32m✓\033[0m %s%*s%s\n' "$name" "$pad" "" "$got"; ok=$((ok+1))
  else
    printf '  \033[31m✗\033[0m %s%*s%s (ждали %s)\n' "$name" "$pad" "" "$got" "$want"; bad=$((bad+1))
  fi
}

J='Content-Type: application/json'

echo "── Пробы"
check 200 "healthz"                       curl "$B/healthz"
check 200 "readyz"                        curl "$B/readyz"

echo "── Гость"
check 200 "видит ленту"                   curl "$B/api/news"
check 200 "спрашивает кто он"             curl "$B/api/me"
check 403 "писать не может"               curl -X POST "$B/api/news" -H "$J" -d '{"title":"т","body":"т"}'

echo "── Вход"
# 401 и 429 оба означают «не пустило» — какой именно, зависит от того, сколько
# неудачных попыток уже накопилось за минуту
check "401 429" "неверный пароль отвергнут"     curl -X POST "$B/api/login" -H "$J" -d "{\"login\":\"$ADMIN\",\"password\":\"мимо\"}"
check "401 429" "несуществующий логин отвергнут" curl -X POST "$B/api/login" -H "$J" -d '{"login":"неттакого","password":"любой"}'

# Ограничитель считает попытки на IP за минуту, поэтому два прогона подряд
# упираются в него и валят проверки дальше. Ждём, пока окно закроется.
login() { curl -s -o /dev/null -c "$JAR" -w '%{http_code}' -X POST "$B/api/login" -H "$J" \
            -d "{\"login\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}"; }
if [ "$(login)" = "429" ]; then
  echo "  … ограничитель попыток сработал, жду 62 секунды"
  sleep 62
fi
check 200 "верный пароль принят"          curl -c "$JAR" -X POST "$B/api/login" -H "$J" -d "{\"login\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}"

echo "── Права на запись"
check 201 "админ пишет"                   curl -b "$JAR" -X POST "$B/api/news" -H "$J" -d '{"title":"проверка","body":"из smoke.sh"}'
check 201 "кластер пишет по токену"       curl -X POST "$B/api/news" -H "$J" -H "X-Cluster-Token: $CLUSTER_TOKEN" -d '{"title":"проверка","body":"от кластера"}'
check 403 "чужой токен отвергнут"         curl -X POST "$B/api/news" -H "$J" -H "X-Cluster-Token: не-тот" -d '{"title":"т","body":"т"}'
check 403 "токен с эмодзи не роняет ручку" curl -X POST "$B/api/news" -H "$J" -H "X-Cluster-Token: 🙂" -d '{"title":"т","body":"т"}'
check 403 "подделанная cookie отвергнута" curl -X POST "$B/api/news" -H "$J" -H 'Cookie: hub_session=подделка.подпись' -d '{"title":"т","body":"т"}'

echo "── Проверка входных данных"
check 422 "пустой заголовок"              curl -b "$JAR" -X POST "$B/api/news" -H "$J" -d '{"title":"","body":"текст"}'
# набивку берём однобайтовой (x): tr работает побайтово и от многобайтовой
# кириллицы взял бы только первый байт — вышел бы битый UTF-8, и сервер ругался
# бы на разбор тела вместо длины, то есть тест проверял бы не то
check 422 "текст длиннее лимита"          curl -b "$JAR" -X POST "$B/api/news" -H "$J" -d "{\"title\":\"ок\",\"body\":\"$(head -c 5000 < /dev/zero | tr '\0' 'x')\"}"

echo "── Выход"
check 200 "выход"                         curl -b "$JAR" -c "$JAR" -X POST "$B/api/logout"
check 403 "после выхода писать нельзя"    curl -b "$JAR" -X POST "$B/api/news" -H "$J" -d '{"title":"т","body":"т"}'

rm -f "$JAR"
echo
printf 'Итог: \033[32m%d прошло\033[0m, ' "$ok"
[ "$bad" -eq 0 ] && printf '\033[32m0 провалено\033[0m\n' || printf '\033[31m%d провалено\033[0m\n' "$bad"
exit $(( bad > 0 ))
