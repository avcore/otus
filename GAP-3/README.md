Установка ELK
=============

Описание/Пошаговая инструкция выполнения домашнего задания:
-------------
Для успешного выполнения ДЗ вам необходимо установить ELK (elasticsearch, logstash, kibana).
Базовая операционная система - по вашему выбору.
После успешной установки ELK-стека вам необходимо настроить отправку логов sshd в elasticsearch через logstash.
Для этого вам придется изменить настройку rsyslog.
Проверьте создался ли index в elasticsearch.
После настройки отправки логов в ELK попробуйте настроить визуализацию логов от sshd в kibana.
В качестве результата ДЗ принимается: конфиг rsyslog, конфиг logstash и результат проверки index в elasticsearch, а также скриншот из kibana, если получилось настроить визуализацию.
Критерии оценки:

0 баллов - задание не выполнено
1 балл - задание выполнено успешно


Установка ELK (elasticsearch, logstash, kibana):
----
```
dpkg -i kibana-7.17.4-amd64.deb logstash-7.17.4-amd64.deb elasticsearch-7.17.1-amd64.deb
```
Конфигурация ElasticSearch:
----
```
grep -v '^ *#\|^ *$' /etc/elasticsearch/elasticsearch.yml
	path.data: /var/lib/elasticsearch
	path.logs: /var/log/elasticsearch
	bootstrap.memory_lock: true
	network.host: 127.0.0.1
	http.port: 9200
	discovery.seed_hosts: ["127.0.0.1", "::1"]
	xpack.monitoring.collection.enabled: true
	xpack.monitoring.elasticsearch.collection.enabled: true
```

Конфигурация Logstash:
----
```
grep -v '^ *#\|^ *$' /etc/logstash/logstash.yml
	path.data: /var/lib/logstash
	path.logs: /var/log/logstash
	log.level: info
```

Конфигурация Kibana:
----
```
grep -v '^ *#\|^ *$' /etc/kibana/kibana.yml
	server.port: 5601
	server.host: "202.78.175.35"
	server.maxPayload: 1048576
```

Тестирование работы ElasticSearch:
----
```
curl 127.0.0.1:9200

{
  "name" : "core-srv-04",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "l5bR0_G2SZacS-Iz3FYUPQ",
  "version" : {
    "number" : "7.17.1",
    "build_flavor" : "default",
    "build_type" : "deb",
    "build_hash" : "e5acb99f822233d62d6444ce45a4543dc1c8059a",
    "build_date" : "2022-02-23T22:20:54.153567231Z",
    "build_snapshot" : false,
    "lucene_version" : "8.11.1",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
```


Конфигурация Rsyslog:
----
```
grep -v '^ *#\|^ *$' /etc/rsyslog.conf
	module(load="imuxsock") # provides support for local system logging
	module(load="imudp")
	input(type="imudp" port="514")
	module(load="imtcp")
	input(type="imtcp" port="514")
	module(load="imklog" permitnonkernelfacility="on")
	$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
	$RepeatedMsgReduction on
	$FileOwner syslog
	$FileGroup adm
	$FileCreateMode 0640
	$DirCreateMode 0755
	$Umask 0022
	$PrivDropToUser syslog
	$PrivDropToGroup syslog
	$WorkDirectory /var/spool/rsyslog
	$IncludeConfig /etc/rsyslog.d/*.conf

grep -v '^ *#\|^ *$' /etc/rsyslog.d/50-default.conf
	auth,authpriv.*			/var/log/auth.log
	*.*;auth,authpriv.none		-/var/log/syslog
	kern.*				-/var/log/kern.log
	mail.*				-/var/log/mail.log
	mail.err			/var/log/mail.err
	*.emerg				:omusrmsg:*
	*.* 				@0.0.0.0:514

grep -v '^ *#\|^ *$' /etc/rsyslog.d/01-json-template.conf
	template(name="json-template"
	type="list") {
	constant(value="{")
	constant(value="\"@timestamp\":\"")     property(name="timereported" dateFormat="rfc3339")
	constant(value="\",\"@version\":\"1")
	constant(value="\",\"message\":\"")     property(name="msg" format="json")
	constant(value="\",\"sysloghost\":\"")  property(name="hostname")
	constant(value="\",\"severity\":\"")    property(name="syslogseverity-text")
	constant(value="\",\"facility\":\"")    property(name="syslogfacility-text")
	constant(value="\",\"programname\":\"") property(name="programname")
	constant(value="\",\"procid\":\"")      property(name="procid")
	constant(value="\"}\n")
	}

grep -v '^ *#\|^ *$' /etc/rsyslog.d/60-output.conf
	*.*                         @202.78.175.35:10514;json-template
```


Конфигурация Logstash:
----
```
input {
  tcp {
    port => 8444
    type => syslog
    mode => "client"
    host => "192.168.5.97"
  }
  udp {
    port => 8444
    type => syslog
  }
}

filter {
        if "syslog" in [tags] {
                if [syslog_program] == "sshd" {
                        if "Failed password" in [message] {
                                grok {
                                        break_on_match => false
                                        match => [
                                                "message", "invalid user %{DATA:UserName} from %{IP:src_ip}",
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Failed_Login" ]
                                }
                        }
                        if "Accepted password" in [message] {
                                grok {
                                        match => [
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Successful_Login" ]
                                }
                        }
                        geoip {
                                source => "src_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                        }
                }
        }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "logstash-sysloghaproxy-%{+YYYY.MM.dd}"
      }
   }
}
```

Установленный стек ELK:
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-es-2022-06-23_19-29.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-lgs-2022-06-23_19-29.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-kib-2022-06-23_19-30.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-1-rsys-2022-06-23_19-30.png)

К сожалению: Не удалось выполнить реализацию: визуализации логов от sshd в kibana
----
Не хватило вычислительных ресурсов: 
	- CPU  (ЦП перегружен...)
	- Disk (логи быстро укладывают всё свободное место на диске)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-2-1-CPU-100-2022-06-23_01-44.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/elk-logs-0-2022-06-24_01-45.png)
