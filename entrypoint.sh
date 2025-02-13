#!/bin/bash

if [ "$1" = "web" ]; then
    exec gunicorn -w 4 -b 0.0.0.0:5000 main:app
elif [ "$1" = "celery" ]; then
    exec celery -A app.celery_worker.celery worker --loglevel=info
else
    exec "$@"
fi