# Pinstack Auth Service �

**Pinstack Auth Service** — микросервис для аутентификации и авторизации пользователей в системе **Pinstack**.

## Основные функции:
- Генерация и проверка JWT-токенов (access + refresh).
- Управление сессиями пользователей.
- Поддержка механизма refresh-токенов для продления сессий.
- Аутентификация по email/username и паролю.
- Регистрация новых пользователей.
- Смена паролей с валидацией.

## Технологии:
- **Go** — основной язык разработки.
- **gRPC** — для межсервисной коммуникации.
- **Docker** — для контейнеризации.
- **Prometheus** — для сбора метрик и мониторинга.
- **Grafana** — для визуализации метрик.
- **Loki** — для централизованного сбора логов.
- **Redis** — для кэширования и хранения сессий.

## Архитектура

Проект построен на основе **гексагональной архитектуры (Hexagonal Architecture)** с четким разделением слоев:

### Структура проекта
```
├── cmd/                    # Точки входа приложения
│   ├── server/             # gRPC сервер
│   └── migrate/            # Миграции БД
├── internal/
│   ├── domain/             # Доменный слой
│   │   ├── models/         # Доменные модели (User, RefreshToken)
│   │   └── ports/          # Интерфейсы (порты)
│   │       ├── input/      # Входящие порты (use cases)
│   │       └── output/     # Исходящие порты (репозитории, токен-менеджер, клиенты)
│   ├── application/        # Слой приложения
│   │   └── service/        # Бизнес-логика и сервисы аутентификации
│   └── infrastructure/     # Инфраструктурный слой
│       ├── inbound/        # Входящие адаптеры (gRPC, middleware)
│       └── outbound/       # Исходящие адаптеры (PostgreSQL, JWT, User Client)
├── migrations/             # SQL миграции
└── mocks/                 # Моки для тестирования
```

### Принципы архитектуры
- **Dependency Inversion**: Зависимости направлены к доменному слою
- **Clean Architecture**: Четкое разделение ответственности между слоями
- **Port & Adapter Pattern**: Интерфейсы определяются в domain, реализуются в infrastructure
- **Testability**: Легкое модульное тестирование благодаря dependency injection

### Мониторинг и метрики
Сервис включает полную интеграцию с системой мониторинга:
- **Prometheus метрики**: Автоматический сбор метрик gRPC, базы данных, JWT операций
- **Structured logging**: Интеграция с Loki для централизованного сбора логов
- **Health checks**: Проверки состояния всех компонентов
- **Performance monitoring**: Метрики времени ответа и throughput аутентификации

## CI/CD Pipeline 🚀

### GitHub Actions
Проект использует GitHub Actions для автоматического тестирования при каждом push/PR.

**Этапы CI:**
1. **Code Quality** — форматирование (gofmt), статический анализ (go vet), линтинг (golangci-lint)
2. **Unit Tests** — юнит-тесты с покрытием кода
3. **Integration Tests** — интеграционные тесты с полной инфраструктурой 
4. **Auto Cleanup** — автоматическая очистка Docker ресурсов

### Makefile команды 📋

#### Команды разработки

### Настройка и запуск
```bash
# Запуск легкой среды разработки (только Prometheus stack)
make start-dev-light

# Запуск полной среды разработки (с мониторингом)
make start-dev-full

# Остановка полной среды разработки
make stop-dev-full

# Очистка полной среды разработки
make clean-dev-full
```

### Мониторинг
```bash
# Запуск полного стека мониторинга (Prometheus, Grafana, Loki, ELK)
make start-monitoring

# Запуск только Prometheus stack (Prometheus + Grafana + Loki)
make start-prometheus-stack

# Запуск только ELK stack (Elasticsearch + Logstash + Kibana)
make start-elk-stack

# Остановка мониторинга
make stop-monitoring

# Очистка мониторинга
make clean-monitoring

# Проверка состояния мониторинга
make check-monitoring-health

# Просмотр логов мониторинга
make logs-prometheus       # Логи Prometheus
make logs-grafana         # Логи Grafana
make logs-loki           # Логи Loki
make logs-elasticsearch  # Логи Elasticsearch
make logs-kibana        # Логи Kibana
```

### Доступ к сервисам мониторинга
После запуска `make start-dev-full` доступны:
- **Prometheus**: http://localhost:9090 - метрики и мониторинг
- **Grafana**: http://localhost:3000 (admin/admin) - дашборды и визуализация
- **Loki**: http://localhost:3100 - централизованные логи
- **Kibana**: http://localhost:5601 - анализ логов ELK
- **Elasticsearch**: http://localhost:9200 - поиск по логам
- **PgAdmin**: http://localhost:5050 (admin@admin.com/admin) - управление БД
- **Kafka UI**: http://localhost:9091 - управление Kafka
- **Auth Service Metrics**: http://localhost:8082/metrics - метрики аутентификации

#### Основные команды разработки:
```bash
# Проверка кода и тесты
make fmt                    # Форматирование кода (gofmt)
make lint                   # Проверка кода (go vet + golangci-lint)
make test-unit              # Юнит-тесты с покрытием
make test-integration       # Интеграционные тесты (с Docker)
make test-all               # Все тесты: форматирование + линтер + юнит + интеграционные

# CI локально
make ci-local               # Полный CI процесс локально (имитация GitHub Actions)
```

#### Управление инфраструктурой:
```bash
# Настройка репозиториев
make setup-system-tests        # Клонирует/обновляет pinstack-system-tests репозиторий
make setup-monitoring          # Клонирует/обновляет pinstack-monitoring-service репозиторий

# Запуск инфраструктуры
make start-auth-infrastructure  # Поднимает все Docker контейнеры для тестов
make check-services            # Проверяет готовность всех сервисов

# Интеграционные тесты
make test-auth-integration     # Запускает только интеграционные тесты
make quick-test               # Быстрый запуск тестов без пересборки контейнеров
make quick-test-local         # Быстрый запуск с локальным auth-service

# Остановка и очистка
make stop-auth-infrastructure  # Останавливает все тестовые контейнеры
make clean-auth-infrastructure # Полная очистка (контейнеры + volumes + образы)
make clean                    # Полная очистка проекта + Docker
```

#### Логи и отладка:
```bash
# Просмотр логов сервисов
make logs-user              # Логи User Service
make logs-auth              # Логи Auth Service  
make logs-gateway           # Логи API Gateway
make logs-db                # Логи User Database
make logs-auth-db           # Логи Auth Database
make logs-redis             # Логи Redis

# Redis утилиты для отладки
make redis-cli              # Подключение к Redis CLI
make redis-info             # Информация о Redis
make redis-keys             # Просмотр всех ключей в Redis
make redis-flush            # Очистка всех данных Redis

# Экстренная очистка
make clean-docker-force     # Удаляет ВСЕ Docker ресурсы (с подтверждением)
```

### Зависимости для интеграционных тестов 🐳

Для интеграционных тестов автоматически поднимаются контейнеры:
- **user-db-test** — PostgreSQL для User Service
- **user-migrator-test** — миграции User Service  
- **user-service-test** — User Service (для взаимодействия)
- **auth-db-test** — PostgreSQL для Auth Service
- **auth-migrator-test** — миграции Auth Service
- **auth-service-test** — сам Auth Service
- **api-gateway-test** — API Gateway
- **redis** — Redis для кэширования и сессий

> 📍 **Требования:** Docker, docker-compose  
> 🚀 **Все сервисы собираются автоматически из Git репозиториев**  
> 🔄 **Репозитории `pinstack-system-tests` и `pinstack-monitoring-service` клонируются автоматически при запуске**

### Быстрый старт разработки ⚡

```bash
# 1. Проверить код
make fmt lint

# 2. Запустить юнит-тесты
make test-unit

# 3. Запустить интеграционные тесты
make test-integration

# 4. Или всё сразу
make ci-local

# 5. Запуск полной среды разработки с мониторингом
make start-dev-full

# 6. Очистка после работы
make clean
```

### Особенности 🔧

- **Отключение кеша тестов:** все тесты запускаются с флагом `-count=1`
- **Фокус на Auth Service:** интеграционные тесты тестируют только Auth endpoints
- **Автоочистка:** CI автоматически удаляет все Docker ресурсы после себя
- **Параллельность:** в CI юнит и интеграционные тесты запускаются последовательно
- **JWT токены:** поддержка access и refresh токенов с безопасным хранением
- **Валидация:** строгая валидация email, паролей и входных данных
- **Redis интеграция:** полная поддержка кэширования и управления сессиями
- **Полный мониторинг:** интеграция с Prometheus, Grafana, Loki и ELK stack

> ✅ Сервис готов к использованию.
