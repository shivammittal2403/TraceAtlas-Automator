FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system traceatlas && useradd --system --gid traceatlas --create-home traceatlas
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER traceatlas
WORKDIR /home/traceatlas
VOLUME ["/home/traceatlas/worker-cases"]
CMD ["traceatlas-worker", "--workspace", "/home/traceatlas/worker-cases", "serve", "--poll-seconds", "15"]
