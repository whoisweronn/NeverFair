# NeverFair backend — Vercel / Node.js 24

Node.js закреплён на `24.x` в `package.json`. `.nvmrc` также выбирает Node.js 24.

## Обновление существующего проекта

1. Замените файлы папки `backend` в вашем GitHub-репозитории и отправьте изменения.
   `node_modules`, локальные `.env` и секреты загружать не нужно.
2. В Vercel откройте **Settings → Build and Deployment → Node.js Version**, выберите
   **24.x** и сохраните. Версия в настройках и `package.json` должна совпадать.
3. Если репозиторий содержит весь лаунчер, **Root Directory = backend**.
   Если в корень репозитория загружено только содержимое backend, **Root Directory = .**
   Framework Preset: **Other**. Пользовательский Build Command не требуется:
   Vercel сам собирает функцию `api/launcher.ts`.
4. Существующие переменные окружения Supabase/GitHub/HWID оставьте в Vercel.
5. Сделайте **Redeploy** последнего коммита после сохранения настроек.
   Обновление Node.js применяется к новым развёртываниям.

Проверка на компьютере с Node.js 24:

```powershell
npm ci --ignore-scripts --no-audit --no-fund
npm run check
```

Документация: https://vercel.com/docs/functions/runtimes/node-js/node-js-versions

Изменение версии Node.js не требует повторного выполнения `schema.sql`.
Этот архив обновляет файлы проекта; настройки вашего аккаунта Vercel он не меняет.
