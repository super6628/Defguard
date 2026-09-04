CREATE TABLE IF NOT EXISTS white_label_branding (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    company_name TEXT NOT NULL DEFAULT 'S-Metric',
    product_name TEXT NOT NULL DEFAULT 'S-Metric Secure',
    short_name TEXT NOT NULL DEFAULT 'S-Metric',
    copyright_name TEXT NOT NULL DEFAULT 'S-Metric',
    support_email TEXT NOT NULL DEFAULT '',
    support_url TEXT NOT NULL DEFAULT '',
    documentation_url TEXT NOT NULL DEFAULT 'https://docs.defguard.net/',
    logo_url TEXT NOT NULL DEFAULT '',
    nav_logo_url TEXT NOT NULL DEFAULT '',
    logo_dark_url TEXT NOT NULL DEFAULT '',
    favicon_url TEXT NOT NULL DEFAULT '',
    primary_color TEXT NOT NULL DEFAULT '',
    login_title TEXT NOT NULL DEFAULT '',
    login_subtitle TEXT NOT NULL DEFAULT '',
    setup_title TEXT NOT NULL DEFAULT 'Welcome to S-Metric Secure!',
    setup_subtitle TEXT NOT NULL DEFAULT 'This wizard walks you through the steps to configure your S-Metric Secure instance, connect all necessary components (Edge, Gateway), and finally set up a VPN Location.',
    setup_button_text TEXT NOT NULL DEFAULT 'Configure S-Metric Secure',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO white_label_branding (
    id,
    product_name,
    logo_url,
    nav_logo_url
)
SELECT
    1,
    COALESCE(NULLIF(instance_name, ''), 'S-Metric Secure'),
    COALESCE(NULLIF(main_logo_url, ''), ''),
    COALESCE(NULLIF(nav_logo_url, ''), '')
FROM settings
WHERE id = 1
ON CONFLICT (id) DO NOTHING;
