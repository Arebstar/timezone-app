CREATE TABLE IF NOT EXISTS billing_accounts (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  stripe_customer_id TEXT UNIQUE,
  stripe_subscription_id TEXT UNIQUE,
  plan TEXT NOT NULL DEFAULT 'free',
  status TEXT NOT NULL DEFAULT 'inactive',
  current_period_end TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credit_grants (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  original_amount INTEGER NOT NULL CHECK (original_amount > 0),
  remaining_amount INTEGER NOT NULL CHECK (remaining_amount >= 0),
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (source_type, source_id)
);

CREATE INDEX IF NOT EXISTS credit_grants_fifo_idx
ON credit_grants(user_id, expires_at, created_at)
WHERE remaining_amount > 0;

CREATE TABLE IF NOT EXISTS credit_transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grant_id BIGINT REFERENCES credit_grants(id) ON DELETE SET NULL,
  amount INTEGER NOT NULL CHECK (amount <> 0),
  transaction_type TEXT NOT NULL,
  description TEXT,
  created_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS credit_transactions_user_id_idx
ON credit_transactions(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS stripe_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO billing_accounts (user_id)
SELECT id FROM users
ON CONFLICT (user_id) DO NOTHING;

WITH new_grants AS (
  INSERT INTO credit_grants (
    user_id, original_amount, remaining_amount, source_type, source_id
  )
  SELECT id, 5, 5, 'signup', 'signup:' || id
  FROM users
  ON CONFLICT (source_type, source_id) DO NOTHING
  RETURNING id, user_id, original_amount
)
INSERT INTO credit_transactions (user_id, grant_id, amount, transaction_type, description)
SELECT user_id, id, original_amount, 'signup_grant', 'Free plan signup credits'
FROM new_grants;
