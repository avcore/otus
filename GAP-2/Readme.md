Выполнение практических заданий Grafana - Формирование dashboard's на основе собранных данных метрик с Grafana и Prometheus
=============
Цель:
-------------
Сформировать dashboard на основе собранных данных с Grafana
Описание/Пошаговая инструкция выполнения домашнего задания:
Задачи:
-------------
Для выполнения данного дз воспользуйтесь наработками из предыдущего домашнего задания.
На VM с установленным Prometheus установите Grafana последней версии доступной на момент выполнения дз
Создайте внутри Grafana папки с названиями infra и app
Внутри директории infra создайте дашборд который будет отображать сводную информацию по инфраструктуре (CPU, RAM, Network, etc.)
Внутри директории app создайте дашборд который будет отображать сводную информацию о CMS (доступность компонентов, время ответа, etc.)
Задания:
-------------
Со звездочкой 1 - при помощи Grafana создайте alert о недоступности одного из компонентов CMS и инфраструктуры
Со звездочкой 2 - создайте DrillDown dashboard который будет отображать сводную информацию по инфраструктуре, но нажав на конкретный инстанс можно получить полную информацию

Результат: переиспользуйте репозиторий созданный для сдачи предыдущего ДЗ. 
Дополните Readme описание действий выполненных в результате выполнения данного дз. 
В директорию GAP-2 приложите скриншоты дашбордов которые вы создали.
Критерии оценки:

0 баллов - задание не выполнено
1 балл - задание выполнено успешно

Установка и конфигурация Grafana
------------- 
```
apt update
apt-get install -y gnupg2 curl software-properties-common
curl https://packages.grafana.com/gpg.key | sudo apt-key add -
add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
apt-get -y install grafana
systemctl enable --now grafana-server
ufw allow ssh
ufw allow 3000/tcp
grafana-cli plugins install grafana-image-renderer
```
Настройка и конфигурация Grafana сервера, через web-интерфейс:
-------------

Добавление источников метрик Prometheus & MySQL:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-1-1-12022-06-16_23-26.png)

Добавление Директорий App и Infra:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-1-1-2-2022-06-16_23-39.png)

Создание главного DrillDown дашборда по GAP-2:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/grafana-4_5-2022-06-16_23-06.png)

Переход из главного верхеуровнего дашборда к дашбордам производительности Инстансов:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-5-1-2022-06-16_23-22.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-5-2-2022-06-16_23-23.png)

Переход из главного верхеуровнего дашборда к дашбордам производительности Приложений:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-5-3-2022-06-16_23-23.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/4-5-3-2022-06-16_23-23.png)

Создание УЗ для системы оповещений в телеграм: 
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/XXX)

Создание трешолд-правил срабатывания оповещения: 
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/1-1-tg-alert-2022-06-17_03-11.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/1-2-tg-alert-2022-06-17_03-13.png)
![](https://github.com/avcore/otus/blob/main/screenshots-all/1-3-tg-alert-2022-06-17_03-14.png)

Aleret о недоступности одного из компонентов системы:
----
![](https://github.com/avcore/otus/blob/main/screenshots-all/1-4-tg-alert-2022-06-17_03-16.png)

- [ ] Скриншоты, которые не вошли в отчёт: Readme [доступны по этой ссылке: https://github.com/avcore/otus/blob/main/screenshots-all/ ]
