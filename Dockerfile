FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/ .

EXPOSE 8000

# pip install + migrate corren en cada `docker-compose up` sin necesidad de rebuild.
# Cambios en requirements.txt o nuevas migraciones se aplican automáticamente.
CMD ["sh", "-c", "pip install --quiet -r requirements.txt && python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
