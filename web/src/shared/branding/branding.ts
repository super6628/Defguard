export type BrandingConfig = {
  companyName: string;
  productName: string;
  shortName: string;
  copyrightName: string;
  supportEmail: string;
  supportUrl: string;
  documentationUrl: string;
  logoUrl: string;
  navLogoUrl: string;
  logoDarkUrl: string;
  faviconUrl: string;
  primaryColor: string;
  loginTitle: string;
  loginSubtitle: string;
  setupTitle: string;
  setupSubtitle: string;
  setupButtonText: string;
};

type ServerBranding = {
  company_name: string;
  product_name: string;
  short_name: string;
  copyright_name: string;
  support_email: string;
  support_url: string;
  documentation_url: string;
  logo_url: string;
  nav_logo_url: string;
  logo_dark_url: string;
  favicon_url: string;
  primary_color: string;
  login_title: string;
  login_subtitle: string;
  setup_title: string;
  setup_subtitle: string;
  setup_button_text: string;
};

const STORAGE_KEY = 'white-label-branding';

export const brandingDefaults: BrandingConfig = {
  companyName: 'S-Metric',
  productName: 'S-Metric Secure',
  shortName: 'S-Metric',
  copyrightName: 'S-Metric',
  supportEmail: '',
  supportUrl: '',
  documentationUrl: 'https://docs.defguard.net/',
  logoUrl: '',
  navLogoUrl: '',
  logoDarkUrl: '',
  faviconUrl: '',
  primaryColor: '',
  loginTitle: '',
  loginSubtitle: '',
  setupTitle: 'Welcome to S-Metric Secure!',
  setupSubtitle:
    'This wizard walks you through the steps to configure your S-Metric Secure instance, connect all necessary components (Edge, Gateway), and finally set up a VPN Location.',
  setupButtonText: 'Configure S-Metric Secure',
};

declare global {
  interface Window {
    __WHITE_LABEL__?: Partial<BrandingConfig>;
  }
}

const readSavedBranding = (): Partial<BrandingConfig> => {
  if (typeof window === 'undefined') return {};
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    return saved ? (JSON.parse(saved) as Partial<BrandingConfig>) : {};
  } catch {
    return {};
  }
};

const deploymentBranding = () =>
  typeof window !== 'undefined' ? (window.__WHITE_LABEL__ ?? {}) : {};

const fromServerBranding = (server: ServerBranding): BrandingConfig => ({
  companyName: server.company_name,
  productName: server.product_name,
  shortName: server.short_name,
  copyrightName: server.copyright_name,
  supportEmail: server.support_email,
  supportUrl: server.support_url,
  documentationUrl: server.documentation_url,
  logoUrl: server.logo_url,
  navLogoUrl: server.nav_logo_url,
  logoDarkUrl: server.logo_dark_url,
  faviconUrl: server.favicon_url,
  primaryColor: server.primary_color,
  loginTitle: server.login_title,
  loginSubtitle: server.login_subtitle,
  setupTitle: server.setup_title,
  setupSubtitle: server.setup_subtitle,
  setupButtonText: server.setup_button_text,
});

export const toServerBranding = (config: BrandingConfig): ServerBranding => ({
  company_name: config.companyName,
  product_name: config.productName,
  short_name: config.shortName,
  copyright_name: config.copyrightName,
  support_email: config.supportEmail,
  support_url: config.supportUrl,
  documentation_url: config.documentationUrl,
  logo_url: config.logoUrl,
  nav_logo_url: config.navLogoUrl,
  logo_dark_url: config.logoDarkUrl,
  favicon_url: config.faviconUrl,
  primary_color: config.primaryColor,
  login_title: config.loginTitle,
  login_subtitle: config.loginSubtitle,
  setup_title: config.setupTitle,
  setup_subtitle: config.setupSubtitle,
  setup_button_text: config.setupButtonText,
});

export const branding: BrandingConfig = {
  ...brandingDefaults,
  ...deploymentBranding(),
  ...readSavedBranding(),
};

export const applyBrandingToDocument = () => {
  if (typeof document === 'undefined') return;
  document.title = branding.productName;
  const appName = document.querySelector<HTMLMetaElement>('meta[name="application-name"]');
  if (appName) appName.content = branding.productName;
  const author = document.querySelector<HTMLMetaElement>('meta[name="author"]');
  if (author) author.content = branding.companyName;
  if (branding.faviconUrl) {
    document.querySelectorAll<HTMLLinkElement>('link[rel*="icon"]').forEach((link) => {
      link.href = branding.faviconUrl;
    });
  }
  if (branding.primaryColor) {
    document.documentElement.style.setProperty('--brand-primary', branding.primaryColor);
  } else {
    document.documentElement.style.removeProperty('--brand-primary');
  }
};

export const hydrateBrandingFromServer = async () => {
  if (typeof window === 'undefined') return branding;
  try {
    const response = await fetch('/api/v1/branding', {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return branding;
    const server = fromServerBranding((await response.json()) as ServerBranding);
    Object.assign(branding, {
      ...brandingDefaults,
      ...deploymentBranding(),
      ...server,
      ...readSavedBranding(),
    });
    applyBrandingToDocument();
    window.dispatchEvent(new CustomEvent('branding-updated'));
  } catch {
    // Keep deployment defaults when Core is unavailable during startup.
  }
  return branding;
};

export const saveBranding = (next: BrandingConfig) => {
  Object.assign(branding, next);
  if (typeof window !== 'undefined') window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  applyBrandingToDocument();
  window.dispatchEvent(new CustomEvent('branding-updated'));
};

export const clearLocalBrandingOverride = () => {
  if (typeof window !== 'undefined') window.localStorage.removeItem(STORAGE_KEY);
};

export const resetBranding = () => {
  const next: BrandingConfig = {
    ...brandingDefaults,
    ...deploymentBranding(),
  };
  Object.assign(branding, next);
  clearLocalBrandingOverride();
  applyBrandingToDocument();
  window.dispatchEvent(new CustomEvent('branding-updated'));
  return next;
};
