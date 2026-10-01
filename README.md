# fairway-plugins

Плагины для [Fairway](https://github.com/Crasher69/fairway). Как устроены
плагины, какие у них права и ограничения — в
[docs/PLUGINS.md](https://github.com/Crasher69/fairway/blob/main/docs/PLUGINS.md)
репозитория fairway.

| Плагин | Вид | Что делает |
|---|---|---|
| [hello](plugins/hello) | base | Пишет в лог число прокси, показывает его на своей странице в панели |
| [spaceproxy](plugins/spaceproxy) | base | Держит в конфиге прокси из аккаунта spaceproxy.net: добавляет активные (уже добавленный руками прокси с тем же адресом забирает себе), убирает истёкшие и удалённые, продлевает со своей страницы |
| [proxy6](plugins/proxy6) | base | Держит в конфиге прокси из аккаунта proxy6.net: добавляет активные (уже добавленный руками прокси с тем же адресом забирает себе), убирает истёкшие и удалённые, продлевает со своей страницы |

## Установка

1. Скачайте `<имя>-<версия>.zip` со страницы
   [Releases](https://github.com/Crasher69/fairway-plugins/releases).
2. Распакуйте в каталог плагинов fairway (`-plugins`, по умолчанию
   `<data>/plugins`): получится `plugins/<имя>/manifest.json`,
   `plugin.wasm` и, если есть, `ui/`.
3. В панели: **Плагины ▾ → Управление плагинами → Перечитать папку →
   Включить**, подтвердить права.

## Структура

```
plugins/<имя>/
  manifest.json   # имя совпадает с именем каталога
  main.go         # пакет main, регистрация в init()
  ui/index.html   # необязательно: страница плагина в панели
build.sh          # сборка в dist/
```

Все плагины — пакеты одного Go-модуля. SDK —
`github.com/Crasher69/fairway/plugin-sdk`; своих тегов у него нет, поэтому
подключён по коммиту (pseudo-version). Обновить до свежего main:

```
GOOS=wasip1 GOARCH=wasm go get github.com/Crasher69/fairway/plugin-sdk@main
```

## Сборка

Нужны Go 1.24+, `jq` и `zip`.

```
./build.sh          # все плагины
./build.sh hello    # только перечисленные
```

Результат: `dist/<имя>/` — готовая папка для каталога плагинов, и
`dist/<имя>-<версия>.zip`. Собранное в git не коммитится.

Логику, которая не зовёт хост, можно проверять обычным `go test`
(файлы с вызовами SDK помечены `//go:build wasip1`):

```
go test ./internal/... ./plugins/spaceproxy/ ./plugins/proxy6/
```

## Новый плагин

1. Создайте `plugins/<имя>/` с `manifest.json` и `main.go` (за образец —
   [hello](plugins/hello)).
2. Добавьте строку в таблицу выше.
3. `./build.sh <имя>`, проверьте в fairway.

## Релиз

Релиз делается по тегу `<имя>-v<версия>`; версия должна совпадать с
`version` в манифесте. CI собирает плагин и прикладывает к GitHub Release
zip и `SHA256SUMS`.

```
git tag hello-v0.1.0 && git push origin hello-v0.1.0
```

## Лицензия

[Apache License 2.0](LICENSE). Copyright 2026 Rinat Devetyarov.
