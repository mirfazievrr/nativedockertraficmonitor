# Docker Task & eBPF Security Monitor

Инструмент мониторинга ресурсов, дискового слоя, файловой активности и сетевого трафика Docker-контейнеров на базе eBPF (libbpf CO-RE), cgroups v2 и C++17.

## Возможности

- Сбор метрик контейнеров через cgroups v2: CPU, разделение RAM на анонимную память (`ANON`) и кэш (`CACHE`), размер записываемого слоя (`DISK_RW`).
- Двухуровневое ограничение памяти: выставление `memory.high` при превышении общей памяти (сброс кэша без остановки контейнера) и `memory.max` при росте `ANON`-памяти.
- Подсчёт TX/RX трафика для TCP и UDP через eBPF (`kprobe`/`kretprobe`), расчёт скорости и группировка эфемерных портов.
- Отслеживание доступа к критическим файлам и каталогам (`/etc/shadow`, `/etc/passwd`, `/var/run/docker.sock`, `/root/.ssh`, `/proc/sys`, запись в `/etc/`, `/bin/` и др.) через `tracepoint/syscalls/sys_enter_openat` и `RingBuffer` с фильтрацией процессов `runc`.
- Конфигурация в `monitor.conf` с применением изменений на лету и поддержкой запуска через systemd.

## Требования

- Linux x86_64 (Debian, Ubuntu 22.04+, Kali) с ядром 5.15+
- Включённый BTF (`/sys/kernel/btf/vmlinux`) и cgroups v2
- Docker

## Сборка

Зависимости для Debian / Kali:
```bash
sudo apt update
sudo apt install -y git clang llvm make g++ libbpf-dev bpftool libelf-dev zlib1g-dev docker.io
sudo systemctl enable --now docker

Зависимости для Ubuntu (22.04 / 24.04):

sudo apt update
sudo apt install -y git clang llvm make g++ libbpf-dev linux-tools-common linux-tools-$(uname -r) libelf-dev zlib1g-dev docker.io
sudo systemctl enable --now docker

Клонирование и сборка (make сам сгенерирует vmlinux.h и соберёт eBPF-скелет)

Использование

Для работы требуются права root.

sudo ./monitor           # полный режим (ресурсы, сеть, алерты)
sudo ./monitor showtask  # только ресурсы, диск и алерты ФС
sudo ./monitor shownet   # только сетевой трафик и сетевые алерты
sudo ./monitor --daemon  # фоновый режим с записью в alerts.log

Все сработавшие предупреждения записываются в alerts.log в рабочей директории.

Ручное управление лимитом памяти контейнера:

sudo ./monitor limit <имя_контейнера> 128  # выставить memory.max = 128 MB
sudo ./monitor limit <имя_контейнера> max  # снять ограничения

Автозагрузка через systemd (создаётся /etc/systemd/system/ebpf-monitor.service с
запуском до docker.service):

sudo ./monitor set AUTOSTART=true
sudo ./monitor set AUTOSTART=false
systemctl status ebpf-monitor.service

Конфигурация

При первом запуске создаётся monitor.conf. Изменения подхватываются работающим
монитором без перезапуска.

sudo ./monitor config
sudo ./monitor set ALERT_TX_KBPS=500 ALERT_RX_KBPS=1000
sudo ./monitor set ALERT_PORTS=80,443,8000-9000
sudo ./monitor set SUSPICIOUS_PORTS=20-25,3333,4444,6660-6670
sudo ./monitor set IGNORE_IPS=127.0.0.1,172.17.0.1,8.8.8.8

| Параметр                | Описание                                            | По умолчанию                     |
| :---------------------- | :-------------------------------------------------- | :------------------------------- |
| `AUTOSTART`             | Автозапуск службы до старта Docker (`true`/`false`) | `false`                          |
| `INTERVAL_SEC`          | Интервал обновления и проверок (сек)                | `2`                              |
| `ALERT_TX_KBPS`         | Порог исходящего трафика (KB/s)                     | `200`                            |
| `ALERT_RX_KBPS`         | Порог входящего трафика (KB/s)                      | `500`                            |
| `SOFT_TOTAL_TRIGGER_MB` | Порог общей RAM для мягкого лимита (MB)             | `25`                             |
| `SOFT_HIGH_LIMIT_MB`    | Значение `memory.high` (MB)                         | `60`                             |
| `HARD_ANON_TRIGGER_MB`  | Порог `ANON`\-памяти для жёсткого лимита (MB)       | `45`                             |
| `HARD_MAX_LIMIT_MB`     | Значение `memory.max` (MB)                          | `80`                             |
| `DISK_RW_ALERT_MB`      | Порог записываемого слоя контейнера (MB)            | `25`                             |
| `ALERT_PORTS`           | Порты и диапазоны для алертов по скорости           | `1-65535`                        |
| `SUSPICIOUS_PORTS`      | Чёрный список портов                                | `20-25,3333,4444,6660-6670,9001` |
| `IGNORE_IPS`            | Игнорируемые IP-адреса                              | `127.0.0.1,172.17.0.1`           |

