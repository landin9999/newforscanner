# PHP + Apache
FROM php:8.2-apache

# Enable rewrites + allow .htaccess
RUN a2enmod rewrite headers \
 && printf '<Directory "/var/www/html">\n  AllowOverride All\n  Require all granted\n</Directory>\n' \
      > /etc/apache2/conf-available/allow-htaccess.conf \
 && a2enconf allow-htaccess

WORKDIR /var/www/html
COPY . .

# Simple health file (optional)
RUN echo ok > /var/www/html/health.txt

# Bind Apache to the right port: $PORT (Railway), $WEBSITES_PORT (Azure), else 80
RUN printf '#!/bin/sh\nset -e\nPORT_TO_USE="${PORT:-${WEBSITES_PORT:-80}}"\n'\
'sed -ri "s/^Listen .*/Listen ${PORT_TO_USE}/" /etc/apache2/ports.conf\n'\
'sed -ri "s#\\*:80#*:${PORT_TO_USE}#g" /etc/apache2/sites-available/000-default.conf\n'\
'exec apache2-foreground\n' > /usr/local/bin/run-apache.sh \
 && chmod +x /usr/local/bin/run-apache.sh

EXPOSE 80
CMD ["run-apache.sh"]
