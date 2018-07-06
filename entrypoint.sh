#!/bin/sh

if [ -z `id sarna 2>/dev/null` ]; then
    echo "sarna:x:3000:3000:sarna:/sarna:/bin/sh" >> /etc/passwd
    echo "sarna:x:3000:" >> /etc/group
fi

chown sarna:sarna /sarna/uploaded_data /sarna/static

su -c 'flask db upgrade' sarna
su -c 'gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile - --error-logfile - app:app' sarna