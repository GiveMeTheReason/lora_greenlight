## Инструкция для запуска бота

0. Сборка docker-образа

```
docker build .
```

1. Запустить mongodb без пароля, но с базой (разрабатывалось на mongo 4.4)

```bash
docker run --network host -p 27017:27017 -e MONGO_DATA_DIR=/data/db -e MONGO_INITDB_DATABASE=aiogram_fsm -v $(pwd)/mongo-data:/data/db mongo:4.4
```

2. Дождаться инициализации mongodb

3. Запустить docker контейнер для бота указав те же данные для базы данных mongodb.
Если mongodb запущена без username и password, боту эти значения передавать не нужно

```
docker run --network host -e BOT_TOKEN=<token> -e SERVER_PATH=<server> -e MONGO_INITDB_DATABASE=aiogram_fsm -e MONGO_INITDB_ROOT_USERNAME=<username> -e MONGO_INITDB_ROOT_PASSWORD=<password> <container name>
```


## Список параметров бота

(REQUERED) Set API token from @BotFather
```
BOT_TOKEN=<token>
```

(REQUERED) Базовый адрес сервера для API-запросов (https://stage.thegreenlight.tech/)
```
SERVER_PATH=<server>
```

Ограничение на размер загружаемых фото в мегабайтах (`default=20`).
```
ALLOWED_SIZE=20
```

Через сколько часов после последней авторизации в боте, он снова попросит пароль (`default=24`)
```
HOURS_TO_RELOGIN=24
```

Set mongodb init data. Database name (default="aiogram_fsm"), User (default=None), Password (default=None), Host (default=localhost), Port (default=27017)
```
MONGO_DATABASE=aiogram_fsm
MONGO_USERNAME=None
MONGO_PASSWORD=None
MONGO_HOST=localhost
MONGO_PORT=27017
```

Set logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). (`default=WARNING`)
```
LOGLEVEL=WARNING
```

Set port for prometheus-metrics (`default=9090`)
```
PORT=9090
```

Set folder for downloaded documents (`default=""` local folder)
```
DOCUMENTS_PATH=
```
