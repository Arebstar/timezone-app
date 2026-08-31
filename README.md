# Timezone App v2

Adds free registration, PostgreSQL user storage, password hashing, PostgreSQL-backed sessions, login/logout, and protected timezone routes.

## Local

1. Copy `.env.example` to `.env`.
2. Put strong random values in it.
3. Run `docker compose up -d --build`.
4. Open `http://localhost:3000/register`.

`docker compose down` stops it. `docker compose down -v` also deletes the local database.
