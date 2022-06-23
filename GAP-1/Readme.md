Выполнение практических заданий Prometheus monitoring GAP-1
=============

Цель:
-------------
Результатом выполнения данного дз будет являться публичный репозиторий в системе контроля версий (Github, Gitlab, etc.) в котором будет находится Readme с описание выполненых действий. Файлы конфигурации prometheus и alertmanager должны находится в директории GAP-1
Описание/Пошаговая инструкция выполнения домашнего задания:

Задачи:
-------------
1) На виртуальной машине установите любую open source CMS которая включает в себя следующие компоненты: nginx, php-fpm, database (MySQL or Postgresql)
2) На этой же виртуальной машине установите Prometheus exporters для сбора метрик со всех компонентов системы (начиная с VM и заканчивая DB, не забудьте про blackbox exporter который будет проверять доступность вашей CMS)
3) На этой же или дополнительной виртуальной машине установите Prometheus задачей которого будет раз в 5 секунд собирать метрики с экспортеров
4) На этой же или дополнительной виртуальной машине установите Alertmanager и сконфигурируйте его таким образом чтобы в случае недоступности какого либо компонента был отправлен alert с важность Critical в один из канал оповещений (канал оповещений на выбор: slack or telegram)

Критерии оценки:
-------------
0 баллов - задание не выполнено
1 балл - задание выполнено успешно



Выполнение задания 1: CMS Dumpal9 (nginx, maria-db, php8.0)
-------------
Установка и конфигурация веб-сервера
----    
```
apt update && apt upgrade
mkdir /var/www/html/drupal
apt install nginx -y
tee /etc/nginx/sites-enabled/drupal.conf <<EOF
server {
    listen 80;
    
    root /var/www/html/drupal;

    index index.php index.html index.htm;

    server_name drupal.akornev.com;

    location / {
        try_files $uri $uri/ /index.php$is_args$args;
    }

    location = /favicon.ico { log_not_found off; access_log off; }
    location = /robots.txt { log_not_found off; access_log off; allow all; }
    location ~* .(css|gif|ico|jpeg|jpg|js|png)$ {
        expires max;
        log_not_found off;
    }

    location ~ .php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
```
Установка СУБД
----
```
apt install mariadb-server mariadb-client -y
mysql_secure_installation
```
Создание БД
----
```
mysql -u root -p
mysql> CREATE DATABASE drupal9;
mysql> CREATE USER 'drupal9_user'@'IP_address' IDENTIFIED BY 'm0d1fyth15';
mysql> GRANT ALL PRIVILEGES ON wp.* TO 'drupal9_user'@'IP_address';
mysql> FLUSH PRIVILEGES;
mysql> q
```
Установка PHP
----
```
apt install php8.0 libapache2-mod-php8.0 php8.0-{common,mbstring,xmlrpc,soap,gd,xml,intl,mysql,cli,zip,curl,fpm} -y
systemctl restart nginx
```
Установка Dumpal9
----
```
cd /var/www/html
wget https://ftp.drupal.org/files/projects/drupal-9.3.3.tar.gz
tar xzvf drupal-9.3.3.tar.gz -C /var/www/html/drupal --strip-components=1
chown -R www-data. /var/www/html/drupal
```
Установка SSL Сертификатов
----
```
apt install python3-certbot-nginx
certbot --nginx
```
Результат:
![](https://github.com/avcore/otus/blob/main/screenshots-all/2022-06-16_19-09.png)

Выполнение задания 2-3: Установка Prometheus и Prometheus exporters сбор метрик производительности и приложений
-------------
Установка и конфигурация Prometheus
---- 
```
groupadd --system prometheus
useradd -s /sbin/nologin --system -g prometheus prometheus
mkdir /var/lib/prometheus
for i in rules rules.d files_sd; do  mkdir -p /etc/prometheus/${i}; done
apt update && apt -y install wget curl vim
mkdir -p /tmp/prometheus && cd /tmp/prometheus
curl -s https://api.github.com/repos/prometheus/prometheus/releases/latest | grep browser_download_url | grep linux-amd64 | cut -d '"' -f 4 | wget -qi -
tar xvf prometheus*.tar.gz
cd prometheus*/
mv prometheus promtool /usr/local/bin/
prometheus --version
promtool --version
mv prometheus.yml /etc/prometheus/prometheus.yml
mv consoles/ console_libraries/ /etc/prometheus/
cd $HOME
tee /etc/prometheus/prometheus.yml <<EOF
# my global config
global:
  scrape_interval: 5s # Set the scrape interval to every 5 seconds. Default is every 1 minute.
  evaluation_interval: 5s # Evaluate rules every 5 seconds. The default is every 1 minute.
  # scrape_timeout is set to the global default (10s).

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
           - alertmanager:9093

# Load rules once and periodically evaluate them according to the global 'evaluation_interval'.
rule_files:
  - "custom_alerts.yml"
  # - "first_rules.yml"
  # - "second_rules.yml"

# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Prometheus itself.
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: "prometheus"

    # metrics_path defaults to '/metrics'
    # scheme defaults to 'http'.

    static_configs:
      - targets: ["localhost:9090"]

        # Linux Servers
  - job_name: linux-server1
    static_configs:
      - targets: ['localhost:9100']
        labels:
          alias: server1

            #- job_name: apache-linux-server2
            #static_configs:
            #- targets: ['1.1.10.2:9100']
            #labels:
            #alias: server2

  - job_name: mysql-ty
    static_configs:
      - targets: ['5.188.150.91:9104']
        labels:
          alias: db1

  - job_name: check_http
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
        - http://5.188.150.91/user/login
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  - job_name: check_ssh
    metrics_path: /probe
    params:
      module: [ssh_banner]
    static_configs:
      - targets:
        - 5.188.150.91:22
        - 5.188.150.214:22
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9115

  - job_name: blackboxq
    metrics_path: /probe
    params:
      module: [icmp]
    static_configs:
      - targets:
        - localhost
        - 5.188.150.91
        - 5.188.150.214
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9115

  - job_name: blackboxstat
    metrics_path: /probe
    scrape_timeout: 5s
    params:
      module: [https_2xx]
    static_configs:
      - targets:
        - http://localhost:4000
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9101
EOF
tee /etc/systemd/system/prometheus.service<<EOF
[Unit]
Description=Prometheus
Documentation=https://prometheus.io/docs/introduction/overview/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/usr/local/bin/prometheus   --config.file=/etc/prometheus/prometheus.yml   --storage.tsdb.path=/var/lib/prometheus   --web.console.templates=/etc/prometheus/consoles   --web.console.libraries=/etc/prometheus/console_libraries   --web.listen-address=0.0.0.0:9090   --web.external-url=

SyslogIdentifier=prometheus
Restart=always

[Install]
WantedBy=multi-user.target
EOF
for i in rules rules.d files_sd; do chown -R prometheus:prometheus /etc/prometheus/${i}; done
for i in rules rules.d files_sd; do chmod -R 775 /etc/prometheus/${i}; done
chown -R prometheus:prometheus /var/lib/prometheus/
systemctl daemon-reload && sleep 3 && systemctl start prometheus && sleep 3 && systemctl enable prometheus
ufw allow 9090/tcp
```
Конфигурация аутентификации к Prometheus
----
```
apt update && apt install python3-bcrypt -y
tee ~/gen-pass.py <<EOF
import getpass
import bcrypt

password = getpass.getpass("password: ")
hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
print(hashed_password.decode())
EOF
python3 gen-pass.py
tee /etc/prometheus/web.yml <<EOF
basic_auth_users:
       admin: '$2b$12$.9J0cFyfcLaNjwBW9McDWObbLjM0n0Wb0ToW9wZArxfmwVlctK8SS'
EOF
promtool check web-config /etc/prometheus/web.yml
echo '--web.config.file=/etc/prometheus/web.yml' >> /etc/systemd/system/prometheus.service
systemctl daemon-reload && sleep 3 && systemctl start prometheus && sleep 3 && systemctl enable prometheus
curl -u admin http://localhost:9090/metrics
    Enter host password for user 'admin': <Enter the set password>
    Unauthorized
```
Результат:
![](https://github.com/avcore/otus/blob/main/screenshots-all/2-1_2022-06-14_17-02-15.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/2-2_2022-06-14_17-03-03.png)

Установка и конфигурация Prometheus exporters: srv-performance, mysql
---- 
Prometheus exporters: srv-performance
----
```
groupadd --system prometheus
useradd -s /sbin/nologin --system -g prometheus prometheus
curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest | grep browser_download_url | grep linux-amd64 |  cut -d '"' -f 4 | wget -qi -
tar xvf node_exporter-*linux-amd64.tar.gz
cd node_exporter*/ && mv node_exporter /usr/local/bin/
node_exporter  --version
tee /etc/systemd/system/node_exporter.service <<EOF
[Unit]
Description=Prometheus
Documentation=https://github.com/prometheus/node_exporter
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=prometheus
Group=prometheus
ExecReload=/bin/kill -HUP $MAINPID
ExecStart=/usr/local/bin/node_exporter \
    --collector.cpu \
    --collector.diskstats \
    --collector.filesystem \
    --collector.loadavg \
    --collector.meminfo \
    --collector.filefd \
    --collector.netdev \
    --collector.stat \
    --collector.netstat \
    --collector.systemd \
    --collector.uname \
    --collector.vmstat \
    --collector.time \
    --collector.mdadm \
    --collector.zfs \
    --collector.tcpstat \
    --collector.bonding \
    --collector.hwmon \
    --collector.arp \
    --web.listen-address=localhost:9100 \
    --web.telemetry-path="/metrics"

[Install]
WantedBy=default.target
EOF
systemctl start node_exporter && sleep 3 && systemctl enable node_exporter
ufw allow 9100
tee /etc/init.d/node_exporter <<EOF
#!/bin/bash
# Source function library.
. /etc/rc.d/init.d/functions

RETVAL=0
PROGNAME=node_exporter
PROG=/usr/local/bin/${PROGNAME}
RUNAS=prometheus
LOCKFILE=/var/lock/subsys/${PROGNAME}
PIDFILE=/var/run/${PROGNAME}.pid
LOGFILE=/var/log/${PROGNAME}.log
DAEMON_SYSCONFIG=/etc/sysconfig/${PROGNAME}

# GO CPU core Limit

#GOMAXPROCS=$(grep -c ^processor /proc/cpuinfo)
GOMAXPROCS=1

# Source config

. ${DAEMON_SYSCONFIG}

start() {
    if [[ -f $PIDFILE ]] > /dev/null; then
        echo "node_exporter  is already running"
        exit 0
    fi

    echo -n "Starting node_exporter  service…"
    daemonize -u ${USER} -p ${PIDFILE} -l ${LOCKFILE} -a -e ${LOGFILE} -o ${LOGFILE} ${PROG} ${ARGS}
    RETVAL=$?
    echo ""
    return $RETVAL
}

stop() {
    if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
        echo "Service not running"
        return 1
    fi
    echo 'Stopping service…'
    #kill -15 $(cat "$PIDFILE") && rm -f "$PIDFILE"
    killproc -p ${PIDFILE} -d 10 ${PROG}
    RETVAL=$?
    echo
    [ $RETVAL = 0 ] && rm -f ${LOCKFILE} ${PIDFILE}
    return $RETVAL
}

status() {
    if [ -f "$PIDFILE" ] || kill -0 $(cat "$PIDFILE"); then
      echo "apache exporter  service running..."
      echo "Service PID: `cat $PIDFILE`"
    else
      echo "Service not running"
    fi
     RETVAL=$?
     return $RETVAL
}

# Call function
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 2
esac
EOF
tee /etc/sysconfig/node_exporter <<EOF
--collector.cpu 
--collector.diskstats 
--collector.filesystem 
--collector.loadavg 
--collector.meminfo 
--collector.filefd 
--collector.netdev 
--collector.stat 
--collector.netstat 
--collector.systemd 
--collector.uname 
--collector.vmstat 
--collector.time 
--collector.mdadm 
--collector.xfs 
--collector.zfs 
--collector.tcpstat 
--collector.bonding 
--collector.hwmon 
--collector.arp 
--web.listen-address=5.188.150.91:9100
EOF
/etc/init.d/node_exporter
systemctl start node_exporter
systemctl enable node_exporter
vim /etc/prometheus/prometheus.yml
    ...
    # Linux Servers
      - job_name: apache-linux-server1
        static_configs:
          - targets: ['5.188.150.91:9100']
            labels:
              alias: server1

      - job_name: apache-linux-server2
        static_configs:
          - targets: ['5.188.150.214:9100']
            labels:
              alias: server2
    ...
systemctl restart prometheus
```
Prometheus exporters: mysql
----
```
curl -s https://api.github.com/repos/prometheus/mysqld_exporter/releases/latest   | grep browser_download_url   | grep linux-amd64 | cut -d '"' -f 4   | wget -qi -
tar xvf mysqld_exporter*.tar.gz
mv  mysqld_exporter-*.linux-amd64/mysqld_exporter /usr/local/bin/
chmod +x /usr/local/bin/mysqld_exporter
mysqld_exporter  --version
mysql -u root -p
MYSQL > CREATE USER 'mysqld_exporter'@'localhost' IDENTIFIED BY 'StrongPassword' WITH MAX_USER_CONNECTIONS 2;
MYSQL > GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'mysqld_exporter'@'localhost';
MYSQL > FLUSH PRIVILEGES;
MYSQL > EXIT
tee /etc/.mysqld_exporter.cnf <<EOF
[client]
user=mysqld_exporter
password=p@$$w0rD
EOF
chown root:prometheus /etc/.mysqld_exporter.cnf
tee /etc/systemd/system/mysql_exporter.service <<EOF
[Unit]
Description=Prometheus MySQL Exporter
After=network.target
User=prometheus
Group=prometheus

[Service]
Type=simple
Restart=always
ExecStart=/usr/local/bin/mysqld_exporter 
--config.my-cnf /etc/.mysqld_exporter.cnf 
--collect.global_status 
--collect.info_schema.innodb_metrics 
--collect.auto_increment.columns 
--collect.info_schema.processlist 
--collect.binlog_size 
--collect.info_schema.tablestats 
--collect.global_variables 
--collect.info_schema.query_response_time 
--collect.info_schema.userstats 
--collect.info_schema.tables 
--collect.perf_schema.tablelocks 
--collect.perf_schema.file_events 
--collect.perf_schema.eventswaits 
--collect.perf_schema.indexiowaits 
--collect.perf_schema.tableiowaits 
--collect.slave_status 
--web.listen-address=5.188.150.91:9104

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && sleep 3 && systemctl enable mysql_exporter && sleep 3 && systemctl start mysql_exporter
vim /etc/prometheus/prometheus.yml
    ...
      - job_name: mysql-ty
        static_configs:
          - targets: ['5.188.150.91:9104']
            labels:
              alias: db1
    ...
```
Blackbox exporters: status web CMS:
----
```
wget https://github.com/prometheus/blackbox_exporter/releases/download/v0.12.0/blackbox_exporter-0.12.0.linux-amd64.tar.gz
tar -xzf blackbox_exporter-*.linux-amd64.tar.gz
cd blackbox_exporter-*
./blackbox_exporter
vim /etc/prometheus/prometheus.yml 
    ...
      - job_name: blackboxq
        metrics_path: /probe
        params:
          module: [icmp]
        static_configs:
          - targets:
            - localhost
            - 5.188.150.91
            - 5.188.150.214
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: 127.0.0.1:9115
    ...
tee /etc/prometheus/blackbox.yml <<EOF
modules:
  http_2xx:
    prober: http
  http_post_2xx:
    prober: http
    http:
      preferred_ip_protocol: "ip4"
      method: POST
  tcp_connect:
    prober: tcp
  pop3s_banner:
    prober: tcp
    tcp:
      query_response:
      - expect: "^+OK"
      tls: true
      tls_config:
        insecure_skip_verify: false
  ssh_banner:
    prober: tcp
    tcp:
      query_response:
      - expect: "^SSH-2.0-"
  irc_banner:
    prober: tcp
    tcp:
      query_response:
      - send: "NICK prober"
      - send: "USER prober prober prober :prober"
      - expect: "PING :([^ ]+)"
        send: "PONG ${1}"
      - expect: "^:[^ ]+ 001"
  icmp:
    prober: icmp
  icmp_ipv4:
   prober: icmp
   icmp:
     preferred_ip_protocol: ip4
EOF
```

Выполнение задания 4: Alertmanager
-------------
```
Prometheus --> Alertmanager --> Telepush API --> Telegram
```
Конфигурация Alertmanager
----
```
tee /etc/prometheus/alertmanager.yml <<EOF
# Sample configuration.
# See https://prometheus.io/docs/alerting/configuration/ for documentation.

global:
route:
  group_by: ['alertname']
  group_wait: 10s       # wait up to 10s for more alerts to group them
  receiver: 'telepush'  # see below

# telepush configuration here
receivers:
- name: 'telepush'
  webhook_configs:
  - url: 'https://telepush.dev/api/inlets/alertmanager/9888fd'    # add your Telepush token here
    http_config:

templates: 
- '/etc/prometheus/alertmanager_templates/*.tmpl'
route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 3h 
  receiver: team-X-mails
  routes:
  - match_re:
      service: ^(foo1|foo2|baz)$
    receiver: team-X-mails
    routes:
    - match:
        severity: critical
      receiver: team-X-pager
  - match:
      service: files
    receiver: team-Y-mails

    routes:
    - match:
        severity: critical
      receiver: team-Y-pager
  - match:
      service: database
    receiver: team-DB-pager
    group_by: [alertname, cluster, database]
    routes:
    - match:
        owner: team-X
      receiver: team-X-pager
    - match:
        owner: team-Y
      receiver: team-Y-pager

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'cluster', 'service']


receivers:
- name: 'team-X-mails'
  email_configs:
  - to: 'team-X+alerts@example.org'

- name: 'team-X-pager'
  email_configs:
  - to: 'team-X+alerts-critical@example.org'
  pagerduty_configs:
  - service_key: <team-X-key>

- name: 'team-Y-mails'
  email_configs:
  - to: 'team-Y+alerts@example.org'

- name: 'team-Y-pager'
  pagerduty_configs:
  - service_key: <team-Y-key>

- name: 'team-DB-pager'
  pagerduty_configs:
  - service_key: <team-DB-key>
EOF

curl -X POST http://localhost:9093/-/reload
vim /etc/prometheus/prometheus.yml
    ...
    alerting:
      alertmanagers:
      - static_configs:
        - targets:
           - "localhost:9093"                   # address of your alertmanager service

    rule_files:
      - "custom_alerts.yml"
    ...

tee /etc/prometheus/custom_alert.yml <<EOF
- name: BlackboxAlerts
  rules:
  - alert: EndpointDown
    expr: probe_success == 0
    for: 1m
    labels:
      severity: "critical"
    annotations:
      summary: "Endpoint {{ $labels.instance }} down"
EOF

tee /etc/prometheus/blackbox.yml <<EOF
modules:
  http_2xx:
    prober: http
EOF
```
Результаты Заданий 2-4:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/3-1_2022-06-16_20-47.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/3-2_2022-06-16_20-48.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/3-3_2022-06-16_20-49.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/3_2022-06-16_20-35.png)

