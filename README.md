# NeverFair backend — Python 3.14 / Vercel

Полный backend перенесён с TypeScript на Python. Точка входа — `api/launcher.py`,
класс `handler(BaseHTTPRequestHandler)`. Используется стандартная библиотека Python;
установка сторонних пакетов не требуется. Версия закреплена в `.python-version`
и `pyproject.toml`. Vercel обслуживает функцию по прежнему адресу `/api/launcher`.

## Обновление существующего Vercel-проекта

1. **Замените прежнюю папку backend целиком** содержимым этого архива и отправьте
   изменения в GitHub. При копировании поверх старых файлов обязательно удалите:
   `api/launcher.ts`, `package.json`, `package-lock.json`, `tsconfig.json`, `.nvmrc`.
   В `api` должна остаться только Python-точка входа, иначе появятся две функции
   с одинаковым маршрутом. Не загружайте `node_modules`, `.venv`, `.env` или кэши.
2. В Vercel оставьте существующий проект и домен, чтобы адрес API в лаунчере и
   моде остался прежним. **Framework Preset: Other**. Уберите старые команды
   `npm ci`, `npm install`, `npm run ...` из Install/Build Command, если они были
   заданы вручную; используйте значения по умолчанию. Версия Node.js в интерфейсе
   не выбирает runtime этой функции: маршрут теперь создаётся из `.py` файла.
3. **Root Directory = backend**, если репозиторий содержит папку `backend`.
   Если в корне репозитория лежат её файлы (`api`, `vercel.json`, `pyproject.toml`),
   Root Directory должна указывать на корень (`.`).
4. Сохраните прежние переменные Supabase/GitHub, включая **тот же HWID_PEPPER**.
   Их названия приведены в `.env.example`. Настоящие ключи остаются в Vercel.
5. Сделайте Redeploy нового коммита. Первый запуск после смены runtime можно
   выполнить с выключенным использованием предыдущего Build Cache.

Изменения уже внесены в `Desktop/NeverFairLauncher/backend`; архив содержит
эти же исходники. Развёртывание в вашем аккаунте Vercel этим архивом не выполняется.
Публикуйте новый коммит в том же проекте: новый домен потребует изменения адреса
API в исходниках лаунчера и мода.

## Совместимость

В 1.4.0 добавлен канал `26.2`. Для него загрузите `neverfair-26.2-v1.jar` и
`neverfair-26.2-v1.json` в Release с тегом `26.2` (или задайте `GITHUB_TAG_26_2`).
JSON должен указывать `minecraftVersion: "26.2"`, совместимый Fabric Loader и
имена JAR-зависимостей. Новая версия backend требует Redeploy, без SQL-миграции.
Роли схемы остаются `user` и `admin`; дополнительных ролей для alpha/beta нет.


Сохранён POST `/api/launcher` с JSON `{ "action": "...", "hwid": "...", "payload": {} }`
и заголовком `Authorization: Bearer ...` для действий аккаунта. Ответы и коды
ошибок совместимы с текущим C# лаунчером и Java-модом; пересобирать их не нужно.

Доступны все прежние действия:

- `register`, `login`, `refresh`, `logout`;
- `catalog`, `prepare`, `event`;
- `modVerify`;
- `adminUsers`, `adminReset`, `adminLogs`.

Вход продолжает связывать CPU + GPU + Motherboard с профилем. HMAC-SHA256,
формат данных и RPC Supabase сохранены. Обновление Python не требует миграции
существующей базы: **не запускайте schema.sql повторно**. Новые установки
используют тот же `schema.sql` один раз. Существующие пользователи, HWID и сессии
сохраняются при использовании прежнего проекта Supabase и прежнего HWID_PEPPER.

Мод проверяется до запуска модулей, никогда не привязывает HWID сам и не
передаёт ключи Supabase. Без User ID от лаунчера HWID должен соответствовать
ровно одному профилю. После сброса HWID требуется новый вход в лаунчер; уже
запущенная игра принудительно не закрывается. Админские права проверяет сервер,
а сброс выполняется через атомарный `nf_reset` с отзывом сессий.

## Сборки GitHub

Теги каналов: `release`, `beta`, `alpha` или значения `GITHUB_TAG_*` в Vercel.
К каждому `neverfair-alpha-v0.2.7.jar` в GitHub Release добавляется одноимённый
`neverfair-alpha-v0.2.7.json` (аналогично для других каналов). JAR до 256 МиБ.
Проверка SHA-256, безопасных имён, манифеста и зависимостей сохранена.

Обычный путь — временный URL GitHub. Если GitHub возвращает бинарный файл
вместо перенаправления, backend проверяет его и сохраняет в приватный Storage
`nf-builds`, затем возвращает подписанный URL. В Vercel JAR не возвращается
в теле API. Для существующего бакета при необходимости файла больше 64 МиБ
используйте `migrations/20261019-build-size.sql` и проверьте общий лимит загрузки
вашего проекта Supabase. Это прежнее ограничение Storage, а не новая миграция.

## Локальная проверка

Python 3.14, без npm и pip-пакетов:

```powershell
python -m unittest discover -s tests -v
```

44 проверки покрывают вход/регистрацию, refresh/reset, HWID мода, права admin,
GitHub/Storage, лимиты, редиректы и реальный HTTP-обработчик на loopback. Внешние
Supabase/GitHub подменены: реальные аккаунты не создаются и не изменяются.
Дополнительно при переносе 41 полный ответ сравнен с прежним Node.js backend.
Публикация и вход в живой Vercel/Supabase в этой проверке не выполнялись.

Для запуска с настоящими серверными переменными окружения:

```powershell
python api/launcher.py
```

Адрес: `http://127.0.0.1:8000/api/launcher`. Локальный скрипт не загружает `.env`
самостоятельно. GET возвращает HTTP 405 и JSON `METHOD_NOT_ALLOWED` — это
ожидаемо, API принимает POST. Для настоящего входа используйте HTTPS домен Vercel.
Не помещайте server/service_role ключ в лаунчер, мод или публичный репозиторий.

## Документация Vercel

- [Python runtime и зависимости](https://vercel.com/docs/functions/runtimes/python)
- [Функции в api и BaseHTTPRequestHandler](https://vercel.com/docs/functions/runtimes/python/api-directory)
- [Выбор Python 3.14](https://vercel.com/docs/functions/runtimes/python/python-version)
