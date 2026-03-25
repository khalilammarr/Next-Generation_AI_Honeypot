# Use a lightweight python image
FROM python:3.11-slim

WORKDIR /app

RUN pip install fastapi uvicorn requests

COPY ./agent.py .

CMD ["python", "agent.py"]
