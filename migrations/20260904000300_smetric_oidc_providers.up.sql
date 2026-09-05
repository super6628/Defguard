CREATE TABLE smetric_oidc_provider (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    display_name TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    auto_create BOOLEAN NOT NULL DEFAULT FALSE,
    username_handling TEXT NOT NULL DEFAULT 'prune_email_domain',
    disable_password_management BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_oidc_provider_tenant_not_generic CHECK (
        lower(tenant_id) NOT IN ('common', 'organizations', 'consumers')
    ),
    CONSTRAINT smetric_oidc_provider_username_handling CHECK (
        username_handling IN ('remove_forbidden', 'replace_forbidden', 'prune_email_domain')
    )
);

CREATE UNIQUE INDEX smetric_oidc_provider_one_default
    ON smetric_oidc_provider (is_default)
    WHERE is_default = TRUE;

CREATE INDEX smetric_oidc_provider_tenant_idx
    ON smetric_oidc_provider (tenant_id);

CREATE INDEX smetric_oidc_provider_enabled_idx
    ON smetric_oidc_provider (enabled);
