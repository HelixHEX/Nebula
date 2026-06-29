use anyhow::Result;
use sqlx::PgPool;

pub async fn run(database_url: &str) -> Result<()> {
    let pool = PgPool::connect(database_url).await?;
    for statement in BETTER_AUTH_SCHEMA {
        sqlx::query(statement).execute(&pool).await?;
    }
    pool.close().await;
    Ok(())
}

const BETTER_AUTH_SCHEMA: &[&str] = &[
    r#"
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT,
        name TEXT,
        image TEXT,
        email_verified BOOLEAN NOT NULL DEFAULT FALSE,
        username TEXT,
        display_username TEXT,
        role TEXT,
        banned BOOLEAN NOT NULL DEFAULT FALSE,
        ban_reason TEXT,
        ban_expires TIMESTAMPTZ,
        two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx
    ON users (email)
    WHERE email IS NOT NULL
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL,
        token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ip_address TEXT,
        user_agent TEXT,
        user_id TEXT NOT NULL,
        impersonated_by TEXT,
        active_organization_id TEXT,
        active BOOLEAN NOT NULL DEFAULT TRUE
    )
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions (user_id)
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        id_token TEXT,
        access_token_expires_at TIMESTAMPTZ,
        refresh_token_expires_at TIMESTAMPTZ,
        scope TEXT,
        password TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS accounts_user_id_idx
    ON accounts (user_id)
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS organization (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        logo TEXT,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS member (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS member_user_id_idx
    ON member (user_id)
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS member_organization_id_idx
    ON member (organization_id)
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS invitation (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT,
        status TEXT NOT NULL,
        inviter_id TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS verifications (
        id TEXT PRIMARY KEY,
        identifier TEXT NOT NULL,
        value TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS two_factor (
        id TEXT PRIMARY KEY,
        secret TEXT NOT NULL,
        backup_codes TEXT,
        user_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT,
        start TEXT,
        prefix TEXT,
        "key" TEXT NOT NULL UNIQUE,
        user_id TEXT NOT NULL,
        refill_interval BIGINT,
        refill_amount BIGINT,
        last_refill_at TIMESTAMPTZ,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        rate_limit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        rate_limit_time_window BIGINT,
        rate_limit_max BIGINT,
        request_count BIGINT,
        remaining BIGINT,
        last_request TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        permissions TEXT,
        metadata TEXT
    )
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS api_keys_user_id_idx
    ON api_keys (user_id)
    "#,
    r#"
    CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        user_id TEXT NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        counter BIGINT NOT NULL,
        device_type TEXT NOT NULL,
        backed_up BOOLEAN NOT NULL DEFAULT FALSE,
        transports TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    "#,
    r#"
    CREATE INDEX IF NOT EXISTS passkeys_user_id_idx
    ON passkeys (user_id)
    "#,
];
