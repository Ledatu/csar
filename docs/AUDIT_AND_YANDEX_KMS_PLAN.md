# CSAR Audit + Yandex KMS Plan

Документ фиксирует:
- найденные слабые места проекта;
- поэтапный план внедрения `Yandex KMS API` без `go-sdk`;
- шаблон для будущих KMS-провайдеров;
- идеи расширения YAML-конфигурации.

## Приоритеты

- `P0` — критично, влияет на безопасность и корректность прод-работы.
- `P1` — высокий приоритет, устойчивость и эксплуатация.
- `P2` — средний, расширяемость и снижение операционных рисков.
- `P3` — улучшения и долгосрочные задачи.

---

## P0 — Критично

### 1) Убрать риск plaintext-секретов в control-plane контракте
Проблема:
- В protobuf есть `SecretDistribution` (передача расшифрованных токенов).
- В координаторе есть `BroadcastSecrets(...)`, который может отправлять plaintext-токены.

Что сделать:
- Депрекейтнуть и удалить путь `SecretDistribution` из `CoordinatorService`.
- Оставить единственный путь: `AuthService.GetEncryptedToken(...)`.
- Обновить комментарии и README, чтобы не было двусмысленной модели.

Критерий готовности:
- В protobuf/коде нет API, передающего plaintext токены между сервисами.

### 2) Ввести production policy для transport security
Проблема:
- Без строгого профиля можно случайно запустить небезопасный режим.

Что сделать:
- Ввести явный профиль окружения (`dev/stage/prod`) и валидацию:
  - в `prod` запретить `allow_insecure`;
  - в `prod` требовать mTLS для `router <-> coordinator`.
- Добавить fail-fast при нарушении policy.

Критерий готовности:
- В прод-профиле небезопасный запуск невозможен.

### 3) Реализовать `yandex` как рабочий provider (без SDK)
Проблема:
- Текущий `internal/kms/yandex.go` — заглушка.

Что сделать:
- Добавить рабочий provider на прямом API (HTTP/gRPC) и заменить заглушку.
- Сохранить fail-closed семантику при ошибках KMS.

Критерий готовности:
- `--kms-provider=yandexapi` работает в интеграционных тестах.

---

## P1 — Высокий приоритет

### 1) Включить runtime-кэширование decrypt операций
Проблема:
- `CachingProvider` существует, но не подключен в bootstrap.
- Каждый запрос может повторно дёргать decrypt/fetch.

Что сделать:
- Подключить `NewCachingProvider(...)` в `cmd/csar/main.go`.
- Добавить конфиг TTL и лимитов кэша.
- Добавить инвалидацию по версии токена.

Критерий готовности:
- Есть заметный cache hit rate, снижение latency и нагрузки на KMS.

### 2) Довести версионирование токенов до end-to-end
Проблема:
- `TokenResponse.version` в proto есть, но не используется полноценно.

Что сделать:
- Добавить `Version` в `TokenEntry` координатора.
- Возвращать `version` из `GetEncryptedToken`.
- Использовать `version` в кэше роутера для инвалидации.

Критерий готовности:
- Ротация токенов приводит к корректному обновлению без рестарта.

### 3) Усилить authN/authZ на Coordinator API
Проблема:
- В режимах без mTLS гранулярная авторизация ограничена.

Что сделать:
- Требовать client identity для production (mTLS CN/SAN allowlist).
- Опционально добавить service JWT для RPC уровня.
- Разделить права на `GetEncryptedToken` и `ListTokenRefs` (least privilege).

Критерий готовности:
- Только доверенные роутеры имеют доступ к token API.

---

## P2 — Средний приоритет

### 1) Шаблон провайдеров KMS (для AWS/GCP/Vault и т.д.)
Что сделать:
- Зафиксировать единый контракт и структуру пакетов:
  - `Name()`, `Encrypt()`, `Decrypt()`, `Health()`, `Capabilities()`.
- Вынести общие middleware:
  - retry/backoff,
  - metrics/tracing,
  - circuit breaker,
  - cache.

Критерий готовности:
- Новый провайдер добавляется по единому шаблону без изменений бизнес-логики роутера.

### 2) Убрать “ложно поддерживаемые” опции
Проблема:
- Поля вроде `discovery_method` есть в конфиге, но не участвуют в runtime.

Что сделать:
- Либо реализовать, либо пометить deprecated/удалить из публичного примера.

Критерий готовности:
- Нет расхождения между заявленной и фактической функциональностью.

### 3) Интеграционные тесты для отказов KMS
Что сделать:
- Добавить сценарии:
  - timeout/retryable errors,
  - auth errors,
  - stale-cache behavior (если включен режим serve-stale).

Критерий готовности:
- Поведение при деградации KMS предсказуемо и тестами закреплено.

---

## P3 — Улучшения

### 1) Реализация `PostgresStore`
Что сделать:
- Реализовать persistency control-plane состояния.
- Добавить миграции и failover-ready режим.

### 2) Расширенная observability
Что сделать:
- Метрики:
  - `kms_encrypt/decrypt_latency`,
  - `kms_errors_total{class}`,
  - `kms_cache_hit_ratio`.
- Трейс-атрибуты по provider/key/op/result.

### 3) Hardening по памяти и логированию
Что сделать:
- Минимизировать lifetime plaintext токенов в памяти.
- Гарантировать redaction во всех security-логах.

---

## План внедрения Yandex KMS API (без go-sdk)

### Этап A — Каркас
- Добавить `YandexAPIProvider` в `internal/kms`.
- Добавить конфиг провайдера (endpoint, auth mode, timeouts, retry policy).

### Этап B — Auth и transport
- Поддержать источники auth:
  - `iam_token`,
  - `oauth_token`,
  - metadata token provider.
- Настроить TLS и timeouts на HTTP клиенте.

### Этап C — Encrypt/Decrypt
- Реализовать прямые вызовы API.
- Нормализовать ошибки (auth, throttling, unavailable, invalid key).

### Этап D — Интеграция в router
- Подключить provider через factory.
- Добавить опциональную обвязку cache/retry/metrics.

### Этап E — Тесты и rollout
- unit + integration + canary rollout.
- SLO/алерты на KMS latency/error/hit-rate.

---

## Предложения по YAML (новые опции)

### Top-level `kms`
```yaml
kms:
  provider: yandexapi
  default_key_id: "abj-xxx"
  operation_timeout: "2s"
  retry:
    max_attempts: 3
    base_delay: "100ms"
    max_delay: "2s"
    jitter: true
  cache:
    enabled: true
    ttl: "60s"
    max_entries: 10000
```

### Route-level `x-csar-security`
```yaml
x-csar-security:
  kms_key_id: "abj-xxx"
  token_ref: "my_api_token"
  token_version: "v42"
  inject_header: "Authorization"
  inject_format: "Bearer {token}"
  on_kms_error: "fail_closed" # fail_closed | serve_stale
```

### Security policy
```yaml
security_policy:
  environment: "prod"
  forbid_insecure_in_prod: true
  require_mtls_for_coordinator: true
  redact_sensitive_logs: true
```

