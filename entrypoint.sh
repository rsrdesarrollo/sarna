#!/bin/sh

#if [ -z $(id sarna 2>/dev/null) ]; then
#  echo "sarna:x:3000:3000:sarna:/sarna:/bin/sh" >>/etc/passwd
#  echo "sarna:x:3000:" >>/etc/group
#fi

#chown sarna:sarna /sarna/uploaded_data /sarna/static

DATABASE_HOST=$(echo $SQLALCHEMY_DATABASE_URI | sed -r 's#\w+://[^:]+:[^@]+@([^/]+)/.*#\1#')
until nc -z -v -w30 $DATABASE_HOST 5432; do
  echo "Waiting for database connection..."
  # wait for 5 seconds before check again
  sleep 5
done

flask db upgrade 9ab3158991e2 2>/dev/null

flask db upgrade
flask assets build

if [ "$FLASK_ENV" == "development" ]; then
  flask run --debugger --host 0.0.0.0
else
  gunicorn -w 4 -b 0.0.0.0:5000 --access-logfile - --error-logfile - app:app
fi
