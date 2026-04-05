# Use a lightweight python image
FROM python:3.11-slim

WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY ./requirements.txt .

# Install the exact libraries needed
RUN pip install --no-cache-dir -r requirements.txt

# Copy all the honey files (agent.py AND personality.txt)
COPY . .

CMD ["python", "agent.py"]
