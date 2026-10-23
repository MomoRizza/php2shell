FROM php:8.1-fpm
RUN echo "memory_limit=512M"                        > /usr/local/etc/php/conf.d/lab.ini && \
    echo "post_max_size=50M"                        >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "upload_max_filesize=50M"                  >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "display_errors=On"                        >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "session.upload_progress.enabled=On"       >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "session.upload_progress.cleanup=On"       >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS" >> /usr/local/etc/php/conf.d/lab.ini && \
    echo "session.save_path=/tmp"                   >> /usr/local/etc/php/conf.d/lab.ini
