# RakLite + proxybox

Проверенная связка:

- `RakSAMP Lite.exe` от **18.04.2022** (SHA256 `0C1AEEAB9ADCF23318A04837CCB1D4EA1210DA2943AC1AF4A9D94A450F733D87`).
- `!!proxy_udp_patch.lua` из BLASTHACK: все 4 патча применяются (`ok`).
- `pb_vision.lua` + UDP-реестр proxybox: тайл с радаром, HUD и чатом.

## Как запускается

1. proxybox определяет RakLite по имени exe (`raksamp`, `raklite`, `rakbot`) и запускает **напрямую**, без `pbhook` — тот проксирует только TCP, а SA-MP идёт по UDP.
2. В `<RakLite>/scripts/` копируются `pb_vision.lua` и `!!proxy_udp_patch.lua`, если их там нет.
3. Для выбранного SOCKS5 поднимается локальный **handshake fix**:
   RakLite шлёт приветствие `05 01 00 00` (лишний нулевой байт), строгие
   SOCKS5-серверы отвечают `bad version`. Мост выбрасывает лишний байт и
   прозрачно проксирует TCP до реального прокси.
4. `pb_vision.lua` вызывает `proxyConnect` и ждёт `isProxyConnected()`;
   патч исправляет UDP ASSOCIATE, relay `0.0.0.0`, ретрай и прямой query.
5. Состояние бота уходит по UDP на proxybox, тайл рисует радар.

## Требования к прокси

- Только **SOCKS5 с UDP ASSOCIATE**. HTTP не подходит.
- В списке proxybox нажми «Найти» или «Проверить»: рабочий прокси
  помечается `· UDP`.
- Бесплатные списки почти не содержат UDP; для реальной работы нужен
  платный/свой SOCKS5 (gost/dante/Shadowsocks) с низким пингом.
- Для проверки без прокси можно выбрать `direct://`: RakLite пойдёт
  напрямую, IP не меняется, но vision и патч работают.

## Локальный тест

Проверено на:

- `open.mp` server v1.6.7.3218, порт 7777, gamemode `gungame`.
- `gost` 3.3.2: `gost -L "socks5://127.0.0.1:1080?udp=true&udpBufferSize=65535"`.
- Два RakLite-бота через proxybox: `ProxyBot2`, `ProxyBot3`; оба в игре,
  оба тайла живые.

Ожидаемый лог RakLite:

```
[LUA] [proxy-patch] udp associate dst: ok
[LUA] [proxy-patch] relay address: ok
[LUA] [proxy-patch] connect retry interval: ok
[LUA] [proxy-patch] direct query: ok
[LUA] [pb_vision] proxy 127.0.0.1:<bridge>
[LUA] [pb_vision] publisher -> 127.0.0.1:<port>
[NET] Connected to ...
```

## Ограничения

- Патч версионный: на другой сборке он напишет `skipped, unexpected bytes`.
- `pb_vision.lua` не перезаписывается, если уже существует; старую версию
  нужно удалить вручную.
- В тайле нет карты SA и 3D-геометрии — только сущности из Lua API.
- Чат в CP1251 может отображаться с `?` (lossy UTF-8).
- Начиная с текущей сборки `pbhook` сам умеет SOCKS5 UDP ASSOCIATE, но RakLite
  идёт своим путём (нативный SOCKS5), поэтому `!!proxy_udp_patch.lua` остаётся
  обязательным. Для обычных приложений ассоциация поднимается автоматически:
  см. `pbproxy: armed … udp=associate` в логе хука.
