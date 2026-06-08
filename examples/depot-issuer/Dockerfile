FROM denoland/deno:2.0.0

WORKDIR /app

# Cache the dependencies as a separate Docker layer.
COPY src/sync.ts src/register.ts /app/src/
RUN deno cache /app/src/sync.ts /app/src/register.ts

# Keys are mounted in at runtime via docker-compose, not baked in.
# Keep the image clean of secrets.

CMD ["deno", "run", "--allow-net", "--allow-read", "--allow-env", "/app/src/sync.ts"]
