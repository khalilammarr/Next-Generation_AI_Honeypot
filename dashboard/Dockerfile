FROM python:3.10-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    openai \
    python-dotenv \
    reportlab

# Copy the application code
# (We map the whole project dir as a volume in docker-compose for easy DB access,
#  but we need a Dockerfile to define the environment)
COPY . .

EXPOSE 8080

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8080"]
