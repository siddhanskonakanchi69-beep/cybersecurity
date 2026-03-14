FROM python:3.10-slim

WORKDIR /app

# Install deps first for caching
COPY ml_models/requirements.txt /app/ml_models/requirements.txt
RUN pip install --no-cache-dir -r ml_models/requirements.txt

# Copy ML code and trained models
COPY ml_models/__init__.py       /app/ml_models/__init__.py
COPY ml_models/serve.py          /app/ml_models/serve.py
COPY ml_models/feature_engineering.py /app/ml_models/feature_engineering.py
COPY ml_models/download_data.py  /app/ml_models/download_data.py
COPY ml_models/train.py          /app/ml_models/train.py
COPY ml_models/test_api.py       /app/ml_models/test_api.py
COPY ml_models/models/           /app/ml_models/models/
COPY ml_models/data/             /app/ml_models/data/

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import requests; r=requests.get('http://localhost:8001/health'); exit(0 if r.status_code==200 else 1)"

CMD ["python", "-m", "ml_models.serve"]
