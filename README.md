# Timezone App

A Dockerized Express and PostgreSQL application for checking the current time, looking up a US ZIP code's timezone, and managing authenticated user accounts.

## Features

- Current local time and browser timezone
- US ZIP code timezone lookup
- User registration with bcrypt password hashing
- PostgreSQL-backed login sessions
- Email two-factor authentication with expiring, single-use codes
- Login, verification, and resend rate limits
- Account page with verified email changes
- Notification to the previous address after an email change
- Admin-only user list
- FIFO credit grants with five free signup credits
- Stripe Pro subscriptions with ten monthly rollover credits
- Audited admin credit gifts
- Application and database health endpoint

## Technology

- Node.js 22 and Express
- PostgreSQL 17
- Docker Compose
- SendGrid SMTP through Nodemailer
- Server-rendered HTML views and plain CSS

## Project structure

```text
server.js                     Application setup and server startup
routes/                       HTTP endpoints grouped by feature
middleware/                   Authentication and rate limiting
services/                     Email delivery and verification codes
utils/                        HTML view and escaping helpers
views/                        Login, verification, account, and admin pages
public/                       Styles and browser-side assets
db/pool.js                    Shared PostgreSQL connection pool
db/init.sql                   Base schema for a new PostgreSQL volume
db/migrate-admin.sql          Adds user roles
db/migrate-2fa.sql            Adds login verification codes
db/migrate-email-change.sql   Adds email-change verification codes
db/migrate-billing.sql        Adds billing, credit, and Stripe event records
compose.yaml                  Local Docker Compose configuration
```

## Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

Configure these values in `.env`:

```env
DB_PASSWORD=replace-with-a-long-random-password
SESSION_SECRET=replace-with-another-long-random-secret
COOKIE_SECURE=false
SENDGRID_API_KEY=replace-with-your-sendgrid-api-key
APP_BASE_URL=http://localhost:3000
STRIPE_SECRET_KEY=sk_test_replace-with-your-test-secret-key
STRIPE_WEBHOOK_SECRET=whsec_replace-with-your-test-webhook-secret
STRIPE_PRO_PRICE_ID=price_replace-with-your-pro-monthly-price-id
```

Use `COOKIE_SECURE=false` for local HTTP development. Set it to `true` when the application is served over HTTPS in production.

The sender configured as `MAIL_FROM` in `compose.yaml` must be authorized by your SendGrid account. Never commit `.env` or actual secrets.

## Stripe test-mode setup

1. In Stripe test mode, create a `Timezone App Pro` product with a recurring monthly price.
2. Copy its `price_...` identifier into `STRIPE_PRO_PRICE_ID`. The webhook accepts monthly credit events only when the subscription contains this exact price and the application metadata matches `timezone-app`.
3. Add a test webhook endpoint pointing to `https://your-domain.example/webhooks/stripe`.
4. Subscribe it to `checkout.session.completed`, `invoice.paid`, `customer.subscription.updated`, and `customer.subscription.deleted`.
5. Copy that endpoint's `whsec_...` signing secret into `STRIPE_WEBHOOK_SECRET`.
6. Configure Stripe's Customer Portal if subscribers should manage payment methods or cancellations.

Stripe Customers are created only when users begin Pro checkout. Credit grants come from signed `invoice.paid` webhooks, are idempotent by Stripe invoice ID, and expire one month after the paid service period ends. This permits at most one month of subscription-credit rollover. Free signup and admin-gift credits do not expire.

Credits are not currently deducted by timezone lookups. Connect `services/credits.js`'s FIFO `consumeCredits` operation only after deciding which product action should cost credits.

## Local setup

Build and start the application and database:

```bash
docker compose up -d --build
```

Apply all migrations. They use `IF NOT EXISTS`, so these commands are safe for both new and existing databases:

```bash
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-admin.sql
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-2fa.sql
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-email-change.sql
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-billing.sql
```

Open [http://localhost:3000/register](http://localhost:3000/register) to create an account.

Useful local URLs:

```text
http://localhost:3000/           Timezone calculator
http://localhost:3000/account    Account settings
http://localhost:3000/health     Health check
http://localhost:3000/admin/users
```

The admin page requires a user whose role is `admin`.

## Make a user an admin

Open PostgreSQL:

```bash
docker exec -it timezone-db psql -U timezone -d timezone
```

Then update the intended account and verify the result:

```sql
UPDATE users
SET role = 'admin'
WHERE email = 'you@example.com';

SELECT id, email, role
FROM users
WHERE email = 'you@example.com';
```

Exit PostgreSQL with `\q`. Log out and back in if the admin page does not become available immediately.

## Routine deployment

After merging a feature into `main`, update the Mac mini checkout:

```bash
cd ~/Desktop/timezone-app
git checkout main
git pull --ff-only origin main
```

Apply only migrations introduced since the previous deployment. For the account email-change release:

```bash
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-email-change.sql
```

For the Stripe credits release, apply this migration before rebuilding the app container:

```bash
docker exec -i timezone-db psql -U timezone -d timezone < db/migrate-billing.sql
```

Rebuild and replace the application container using the server's production Compose file:

```bash
docker compose -f compose.server.yaml up -d --build
```

Verify the deployment:

```bash
docker compose -f compose.server.yaml ps
docker logs timezone-app --tail 100
docker exec timezone-app wget -qO- http://127.0.0.1:3000/health
```

Expected health response:

```json
{"status":"ok","database":"ok"}
```

## Docker commands

Stop the local containers without deleting data:

```bash
docker compose down
```

The PostgreSQL data is stored in the `postgres-data` Docker volume and survives normal rebuilds.

Do not run the following command against an environment whose database you want to keep:

```bash
docker compose down -v
```

The `-v` option deletes the PostgreSQL volume and its stored data.
