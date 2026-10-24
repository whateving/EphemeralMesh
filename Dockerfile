# Ship only relay code; local identities, chat histories and admin secrets never enter the image.
FROM python:3.15.0-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MESH_DB=/data/relay.db
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 mesh \
    && useradd --uid 10001 --gid mesh --no-create-home mesh \
    && mkdir /data && chown mesh:mesh /data
COPY main.py db.py relay_config.py invitation.py invite.py ./
USER 10001:10001
EXPOSE 8000
# One worker owns live connection routing; SQLite retains durable delivery state.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--ws-max-size", "65536", "--ws-max-queue", "16", "--no-access-log"]
