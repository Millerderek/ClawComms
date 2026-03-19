FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x relay_bootstrap.py

ENTRYPOINT ["python", "relay_bootstrap.py"]
CMD ["--help"]
