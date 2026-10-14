# Custom authoritative responder. Zones, keys, and logs are mounted at run
# time (see compose.yml) so the signing key and trust anchor persist.
FROM python:3.14-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY responder/ responder/
ENTRYPOINT ["python", "-m", "responder"]
CMD ["--addr", "0.0.0.0", "--port", "53"]
