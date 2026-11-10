FROM php:8.2-apache

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Install required system packages, libraries, Node.js, and FFmpeg
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpng-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    libzip-dev \
    libicu-dev \
    libonig-dev \
    zip \
    unzip \
    curl \
    ca-certificates \
    ffmpeg \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Configure & Install PHP Extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        mysqli \
        pdo \
        pdo_mysql \
        gd \
        zip \
        bcmath \
        exif \
        intl \
        opcache

# Enable Apache Modules
RUN a2enmod rewrite headers

# Install Composer from official Composer image
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Configure Apache virtual host & AllowOverride for .htaccess
RUN { \
    echo '<Directory /var/www/html>'; \
    echo '    Options Indexes FollowSymLinks'; \
    echo '    AllowOverride All'; \
    echo '    Require all granted'; \
    echo '</Directory>'; \
} >> /etc/apache2/apache2.conf

# Configure Recommended PHP INI & OPcache settings for Production
RUN { \
    echo 'upload_max_filesize = 64M'; \
    echo 'post_max_size = 64M'; \
    echo 'memory_limit = 512M'; \
    echo 'max_execution_time = 300'; \
    echo 'date.timezone = Asia/Phnom_Penh'; \
    echo 'session.save_path = "/var/www/html/php_sessions"'; \
    echo 'opcache.enable = 1'; \
    echo 'opcache.enable_cli = 0'; \
    echo 'opcache.memory_consumption = 256'; \
    echo 'opcache.interned_strings_buffer = 16'; \
    echo 'opcache.max_accelerated_files = 20000'; \
    echo 'opcache.validate_timestamps = 1'; \
    echo 'opcache.revalidate_freq = 2'; \
    echo 'opcache.save_comments = 1'; \
    echo 'opcache.fast_shutdown = 1'; \
} > /usr/local/etc/php/conf.d/vvc-custom.ini

# Set working directory
WORKDIR /var/www/html

# Copy package files first for better caching
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund || true

# Copy composer files and run install
COPY composer*.json ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader || true

# Copy the rest of the application files (filtered by .dockerignore)
COPY --chown=www-data:www-data . /var/www/html/

# Copy React Admin Panel dist to /admin route if dist exists
RUN if [ -d "/var/www/html/admin_panel/dist" ]; then \
        mkdir -p /var/www/html/admin && cp -r /var/www/html/admin_panel/dist/* /var/www/html/admin/ && chown -R www-data:www-data /var/www/html/admin; \
    fi

# Ensure storage & sessions directories exist with proper permissions
RUN mkdir -p /var/www/html/uploads /var/www/html/php_sessions \
    && chown -R www-data:www-data /var/www/html/uploads /var/www/html/php_sessions \
    && chmod -R 775 /var/www/html/uploads /var/www/html/php_sessions

EXPOSE 80

CMD ["apache2-foreground"]
