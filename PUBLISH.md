# Публикация на GitHub

Репозиторий готов к отправке под именем **sentinel-desk**. В локальной папке создана ветка `main`; личное резюме, рабочие логи и SQLite-базы в неё не включены.

## Через Git

1. Войдите на GitHub и создайте **пустой публичный** репозиторий `sentinel-desk`. Не добавляйте README, `.gitignore` или лицензию: они уже есть.
2. В терминале перейдите в локальную папку проекта.
3. Выполните команды, заменив `YOUR_USERNAME` на ваш логин:

```bash
git remote add origin https://github.com/YOUR_USERNAME/sentinel-desk.git
git push -u origin main
```

Git может открыть окно входа в GitHub. Если хотите скрыть email автора, перед отправкой настройте в локальном репозитории свой GitHub noreply email и выполните `git commit --amend --reset-author --no-edit`.

При публикации из ZIP-архива история Git отсутствует. Сначала выполните:

```bash
git init -b main
git add .
git commit -m "Build Sentinel Desk SOC investigation workbench"
```

Если Git попросит имя и email автора, задайте их локально через `git config user.name` и `git config user.email`.

## Оформление репозитория

**Description:** Local SOC workbench: SSH and web log analysis, event correlation, incident triage, SQLite, Python.

**Topics:** `python`, `security`, `soc`, `log-analysis`, `incident-response`, `sqlite`, `monitoring`, `portfolio`.

Во вкладке Actions проверьте выполнение CI. Затем закрепите репозиторий в профиле GitHub. Ссылка для резюме: `https://github.com/YOUR_USERNAME/sentinel-desk`.

## Формулировка для резюме

> Sentinel Desk — учебный SOC-проект на Python и SQLite: нормализация SSH/nginx/JSONL, 5 правил корреляции событий, веб-интерфейс расследований и экспорт отчётов. В репозитории есть автоматические тесты и GitHub Actions.

Укажите, какие части вы самостоятельно изучили или доработали. Не заявляйте об опыте промышленной эксплуатации на основании демо.
