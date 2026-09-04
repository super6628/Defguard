use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, query_as};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, FromRow, PartialEq, Serialize, ToSchema)]
pub struct WhiteLabelBranding {
    pub company_name: String,
    pub product_name: String,
    pub short_name: String,
    pub copyright_name: String,
    pub support_email: String,
    pub support_url: String,
    pub documentation_url: String,
    pub logo_url: String,
    pub nav_logo_url: String,
    pub logo_dark_url: String,
    pub favicon_url: String,
    pub primary_color: String,
    pub login_title: String,
    pub login_subtitle: String,
    pub setup_title: String,
    pub setup_subtitle: String,
    pub setup_button_text: String,
}

impl Default for WhiteLabelBranding {
    fn default() -> Self {
        Self {
            company_name: "S-Metric".into(),
            product_name: "S-Metric Secure".into(),
            short_name: "S-Metric".into(),
            copyright_name: "S-Metric".into(),
            support_email: String::new(),
            support_url: String::new(),
            documentation_url: "https://docs.defguard.net/".into(),
            logo_url: String::new(),
            nav_logo_url: String::new(),
            logo_dark_url: String::new(),
            favicon_url: String::new(),
            primary_color: String::new(),
            login_title: String::new(),
            login_subtitle: String::new(),
            setup_title: "Welcome to S-Metric Secure!".into(),
            setup_subtitle: "This wizard walks you through the steps to configure your S-Metric Secure instance, connect all necessary components (Edge, Gateway), and finally set up a VPN Location.".into(),
            setup_button_text: "Configure S-Metric Secure".into(),
        }
    }
}

impl WhiteLabelBranding {
    pub async fn get<'e, E>(executor: E) -> sqlx::Result<Self>
    where
        E: PgExecutor<'e>,
    {
        Ok(query_as::<_, Self>(
            "SELECT company_name, product_name, short_name, copyright_name, support_email, \
             support_url, documentation_url, logo_url, nav_logo_url, logo_dark_url, favicon_url, \
             primary_color, login_title, login_subtitle, setup_title, setup_subtitle, \
             setup_button_text FROM white_label_branding WHERE id = 1",
        )
        .fetch_optional(executor)
        .await?
        .unwrap_or_default())
    }

    pub async fn save<'e, E>(&self, executor: E) -> sqlx::Result<()>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO white_label_branding (id, company_name, product_name, short_name, \
             copyright_name, support_email, support_url, documentation_url, logo_url, nav_logo_url, \
             logo_dark_url, favicon_url, primary_color, login_title, login_subtitle, setup_title, \
             setup_subtitle, setup_button_text, updated_at) \
             VALUES (1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW()) \
             ON CONFLICT (id) DO UPDATE SET company_name=EXCLUDED.company_name, \
             product_name=EXCLUDED.product_name, short_name=EXCLUDED.short_name, \
             copyright_name=EXCLUDED.copyright_name, support_email=EXCLUDED.support_email, \
             support_url=EXCLUDED.support_url, documentation_url=EXCLUDED.documentation_url, \
             logo_url=EXCLUDED.logo_url, nav_logo_url=EXCLUDED.nav_logo_url, \
             logo_dark_url=EXCLUDED.logo_dark_url, favicon_url=EXCLUDED.favicon_url, \
             primary_color=EXCLUDED.primary_color, login_title=EXCLUDED.login_title, \
             login_subtitle=EXCLUDED.login_subtitle, setup_title=EXCLUDED.setup_title, \
             setup_subtitle=EXCLUDED.setup_subtitle, setup_button_text=EXCLUDED.setup_button_text, \
             updated_at=NOW()",
        )
        .bind(&self.company_name)
        .bind(&self.product_name)
        .bind(&self.short_name)
        .bind(&self.copyright_name)
        .bind(&self.support_email)
        .bind(&self.support_url)
        .bind(&self.documentation_url)
        .bind(&self.logo_url)
        .bind(&self.nav_logo_url)
        .bind(&self.logo_dark_url)
        .bind(&self.favicon_url)
        .bind(&self.primary_color)
        .bind(&self.login_title)
        .bind(&self.login_subtitle)
        .bind(&self.setup_title)
        .bind(&self.setup_subtitle)
        .bind(&self.setup_button_text)
        .execute(executor)
        .await?;
        Ok(())
    }
}
