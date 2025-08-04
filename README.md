# Pinstack Auth Service 🚪

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

## CI/CD Pipeline 🚀

### GitHub Actions
Проект использует GitHub Actions для автоматического тестирования при каждом push/PR.

**Этапы CI:**
1. **Code Quality** — форматирование (gofmt), статический анализ (go vet), линтинг (golangci-lint)
2. **Unit Tests** — юнит-тесты с покрытием кода
3. **Integration Tests** — интеграционные тесты с полной инфраструктурой 
4. **Auto Cleanup** — автоматическая очистка Docker ресурсов

### Makefile команды 📋

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
# Настройка репозитория
make setup-system-tests        # Клонирует/обновляет pinstack-system-tests репозиторий

# Запуск инфраструктуры
make start-auth-infrastructure  # Поднимает все Docker контейнеры для тестов
make check-services            # Проверяет готовность всех сервисов

# Интеграционные тесты
make test-auth-integration     # Запускает только интеграционные тесты
make quick-test               # Быстрый запуск тестов без пересборки контейнеров

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

> 📍 **Требования:** Docker, docker-compose  
> 🚀 **Все сервисы собираются автоматически из Git репозиториев**  
> 🔄 **Репозиторий `pinstack-system-tests` клонируется автоматически при запуске тестов**

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

# 5. Очистка после работы
make clean
```

### Особенности 🔧

- **Отключение кеша тестов:** все тесты запускаются с флагом `-count=1`
- **Фокус на Auth Service:** интеграционные тесты тестируют только Auth endpoints
- **Автоочистка:** CI автоматически удаляет все Docker ресурсы после себя
- **Параллельность:** в CI юнит и интеграционные тесты запускаются последовательно
- **JWT токены:** поддержка access и refresh токенов с безопасным хранением
- **Валидация:** строгая валидация email, паролей и входных данных

> ✅ Сервис готов к использованию.
