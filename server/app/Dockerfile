# Imagen de Paywen Scan: una sola imagen para la API y el worker.
#   API (CMD por defecto): uvicorn en el puerto 8000
#   Worker:                python -m worker
#
# Construir para la EC2 (amd64), también desde un Mac con Apple Silicon:
#   docker build --platform linux/amd64 -t paywen-scan:latest .

FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Usuario sin privilegios: el contenedor no corre como root.
RUN groupadd --system --gid 10001 paywen \
 && useradd --system --uid 10001 --gid paywen --home-dir /app --shell /usr/sbin/nologin paywen

COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=paywen:paywen paywen ./paywen
COPY --chown=paywen:paywen worker.py ./

USER paywen
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# --proxy-headers: la IP real del agente llega desde Caddy en X-Forwarded-For.
# Solo Caddy (en la red interna de Docker) puede hablar con este puerto.
CMD ["uvicorn", "paywen.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
