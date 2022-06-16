##############################################
#Выполнение практических заданий Prometheus monitoring GAP-1
##############################################

#Цель:
Результатом выполнения данного дз будет являться публичный репозиторий в системе контроля версий (Github, Gitlab, etc.) в котором будет находится Readme с описание выполненых действий. Файлы конфигурации prometheus и alertmanager должны находится в директории GAP-1
Описание/Пошаговая инструкция выполнения домашнего задания:

#Задачи:
1) На виртуальной машине установите любую open source CMS которая включает в себя следующие компоненты: nginx, php-fpm, database (MySQL or Postgresql)
2) На этой же виртуальной машине установите Prometheus exporters для сбора метрик со всех компонентов системы (начиная с VM и заканчивая DB, не забудьте про blackbox exporter который будет проверять доступность вашей CMS)
3) На этой же или дополнительной виртуальной машине установите Prometheus задачей которого будет раз в 5 секунд собирать метрики с экспортеров
4) На этой же или дополнительной виртуальной машине установите Alertmanager и сконфигурируйте его таким образом чтобы в случае недоступности какого либо компонента был отправлен alert с важность Critical в один из канал оповещений (канал оповещений на выбор: slack or telegram)

#Критерии оценки:

0 баллов - задание не выполнено
1 балл - задание выполнено успешно

```
test test 
```

##Выполнение задания 1: CMS Dumpal9 (nginx, maria-db, php8.0)
###Установка и конфигурация веб-сервера
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
###Установка СУБД
```
apt install mariadb-server mariadb-client -y
mysql_secure_installation
```
###Создание БД
```
mysql -u root -p
mysql> CREATE DATABASE drupal9;
mysql> CREATE USER 'drupal9_user'@'IP_address' IDENTIFIED BY 'm0d1fyth15';
mysql> GRANT ALL PRIVILEGES ON wp.* TO 'drupal9_user'@'IP_address';
mysql> FLUSH PRIVILEGES;
mysql> q
```
###Установка PHP
```
apt install php8.0 libapache2-mod-php8.0 php8.0-{common,mbstring,xmlrpc,soap,gd,xml,intl,mysql,cli,zip,curl,fpm} -y
systemctl restart nginx
```
###Установка Dumpal9
```
cd /var/www/html
wget https://ftp.drupal.org/files/projects/drupal-9.3.3.tar.gz
tar xzvf drupal-9.3.3.tar.gz -C /var/www/html/drupal --strip-components=1
chown -R www-data. /var/www/html/drupal
```
###Установка SSL Сертификатов
```
apt install python3-certbot-nginx
certbot --nginx
```
Результат:
![](https://github.com/avcore/otus/blob/main/screenshots-all/2022-06-16_19-09.png)
