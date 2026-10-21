FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p static/assets && cp casal-carinho.webp casal-conversa.webp static/assets/
RUN mkdir -p /app/data
ENV APP_ENV=production DB_PATH=/app/data/casais.sqlite3 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
