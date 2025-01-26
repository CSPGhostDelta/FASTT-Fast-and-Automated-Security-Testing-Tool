FROM python:3.9-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /usr/src/app/

RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    libglib2.0-0 \
    libgdk-pixbuf2.0-0 \
    libpango1.0-0 \
    libcairo2 \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ./certs/cert.pem /etc/nginx/certs/cert.pem
COPY ./certs/key.pem /etc/nginx/certs/key.pem
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]