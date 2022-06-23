Установка beats: hearthbeat, filebeat и metricbeat
=============
Описание/Пошаговая инструкция выполнения домашнего задания:
-------------
Для успешного выполнения дз вам нужно сконфигурировать hearthbeat, filebeat и metricbeat.
Heartbeat должен проверять доступность следующих ресурсов: otus.ru, google.com.
Metricbeat должен формировать метрики на основе показателей загрузки процессора и оперативной памяти.
Filebeat должен собирать логи ssh сервера. По собственному усмотрению вы можете собирать логи других сервисов которые присутствуют в системе ^_^
В качестве результата приложите конфиги hearthbeat, filebeat и metricbeat. Скриншот полученных данных отображенных в Kibana.
Критерии оценки:

0 баллов - задание не выполнено
1 балл - задание выполнено успешно

Конфигурация Heartbeat:
----
```
grep -v '^ *#\|^ *$' heartbeat.yml
	heartbeat.config.monitors:
	  path: ${path.config}/monitors.d/*.yml
	  reload.enabled: false
	  reload.period: 5s	
	heartbeat.monitors:
	- type: http
	  enabled: false
	  id: my-monitor
	  name: My Monitor
	  urls: ["http://localhost:9200"]
	  schedule: '@every 4s'
	heartbeat.run_once: true
	setup.template.settings:
	  index.number_of_shards: 1
	  index.codec: best_compression
	setup.kibana:
	  host: "localhost:5601"
	output.elasticsearch:
	  hosts: ["localhost:9200"]
	  protocol: "http"
	  hosts: ["localhost:5044"]
	processors:
	- add_observer_metadata:
	logging.level: debug
	monitoring.enabled: true

grep -v '^ *#\|^ *$' sample.http.yml
	- type: http # monitor type `http`. Connect via HTTP an optionally verify response
	  id: my-http-monitor
	  name: My HTTP Monitor
	  schedule: '@every 5s' # every 5 seconds from start of beat
	  hosts: ["http://localhost:9200", "https://otus.ru:443", "http://google.com:80"]
	  ipv4: true
	  ipv6: true
	  mode: any

grep -v '^ *#\|^ *$' sample.icmp.yml
	- type: icmp # monitor type `icmp` (requires root) uses ICMP Echo Request to ping
	  id: my-icmp-monitor
	  name: My ICMP Monitor
	  schedule: '@every 5s' # every 5 seconds from start of beat
	  hosts: ["localhost", "188.114.96.171", "8.8.8.8"]
	  ipv4: true
	  ipv6: true
	  mode: any
	  timeout: 16s
	  wait: 1s
```

Конфигурация Metricbeat:
----
```
grep -v '^ *#\|^ *$' metricbeat.yml 
	metricbeat.config.modules:
	  path: ${path.config}/modules.d/*.yml
	  reload.enabled: true
	  reload.period: 10s
	setup.template.settings:
	  index.number_of_shards: 1
	  index.codec: best_compression
	setup.dashboards.enabled: true
	setup.kibana:
	  host: "localhost:5601"
	output.elasticsearch:
	  hosts: ["localhost:9200"]
	  protocol: "http"
	output.logstash:
	  hosts: ["localhost:5044"]
	logging.level: debug
	logging.selectors: ["*"]
	logging.to_files: true
	logging.files:
	  path: /var/log/metricbeat
	  name: metricbeat
	  keepfiles: 7
	  permissions: 0644
	monitoring.enabled: true
	monitoring.elasticsearch:
	  hosts: ["localhost:9200"]

grep -v '^ *#\|^ *$' system.yml
	- module: system
	  period: 10s
	  metricsets:
	    - cpu
	    - load
	    - memory
	    - network
	    - process
	    - process_summary
	    - socket_summary
	    - entropy
	    - core
	    - diskio
	    - socket
	    - service
	    - users
	  process.include_top_n:
	    by_cpu: 5      # include top 5 processes by CPU
	    by_memory: 5   # include top 5 processes by memory
	- module: system
	  period: 1m
	  metricsets:
	    - filesystem
	    - fsstat
	  processors:
	  - drop_event.when.regexp:
	      system.filesystem.mount_point: '^/(sys|cgroup|proc|dev|etc|host|lib|snap)($|/)'
	- module: system
	  period: 5m
	  metricsets:
	    - uptime

grep -v '^ *#\|^ *$' kibana-xpack.yml
	- module: kibana
	  metricsets:
	    - stats
	  period: 10s
	  hosts: ["localhost:5601"]
	  xpack.enabled: true

grep -v '^ *#\|^ *$' elasticsearch-xpack.yml
	- module: elasticsearch
	  xpack.enabled: true
	  period: 10s
	  hosts: ["http://localhost:9200"]
```

Конфигурация Filebeat:
----
```
grep -v '^ *#\|^ *$' filebeat.yml 
	filebeat.inputs:
	- type: log
	  enabled: true
	  paths:
	      - /var/log/nginx/*-access.log
	  fields:
	    type: nginx_access
	  fields_under_root: true
	  scan_frequency: 5s
	- type: log
	  enabled: true
	  paths:
	      - /var/log/nginx/*-error.log
	  fields:
	    type: nginx_error
	  fields_under_root: true
	  scan_frequency: 5s
	output.logstash:
	  hosts: ["localhost:5044"]
	xpack.monitoring:
	  enabled: true
	  elasticsearch:
	    hosts: ["http://localhost:9200"]
	filebeat.config.modules:
	  path: ${path.config}/modules.d/*.yml
	  reload.enabled: true
	  setup.dashboards.enabled: true
	  setup.kibana:
	  host: "202.78.175.35:5601"

grep -v '^ *#\|^ *$' system.yml
	- module: system
	  syslog:
	    enabled: true
	  auth:
	    enabled: true
	    var.paths: ["/var/log/secure"]

grep -v '^ *#\|^ *$' nginx.yml
	- module: nginx
	  access:
	    enabled: true
	  error:
	    enabled: true
	  ingress_controller:
	    enabled: false

grep -v '^ *#\|^ *$' kibana.yml
	- module: kibana
	  log:
	    enabled: true
	  audit:
	    enabled: true
```

Скриншоты полученных данных в Kibana:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-2-2022-06-23_01-36.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-32022-06-23_01-37.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-4-core-srv-04-2022-06-23_01-38.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-4-2-core-srv-042022-06-23_01-39.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-6-2022-06-23_01-40.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-6-2022-06-23_01-42.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-6-2-2022-06-23_04-46.png)

