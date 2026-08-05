FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# зависимости отдельным слоем и ДО кода: пока requirements.txt не менялся,
# при пересборке слой берётся из кеша и pip не запускается
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# процесс от обычного пользователя, каталог с кодом остаётся за root —
# приложение не может переписать собственные файлы
RUN useradd --uid 10001 --create-home app
USER 10001

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
