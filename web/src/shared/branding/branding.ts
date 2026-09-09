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
  loginImageUrl: string;
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
  login_image_url: string;
  favicon_url: string;
  primary_color: string;
  login_title: string;
  login_subtitle: string;
  setup_title: string;
  setup_subtitle: string;
  setup_button_text: string;
};

const STORAGE_KEY = 'white-label-branding';
const originalFavicons = new Map<HTMLLinkElement, string>();

export const brandingDefaults: BrandingConfig = {
  companyName: 'S-Metric',
  productName: 'S-Metric Secure',
  shortName: 'S-Metric',
  copyrightName: 'S-Metric',
  supportEmail: '',
  supportUrl: '',
  documentationUrl: '',
  logoUrl: '',
  navLogoUrl: '',
  logoDarkUrl: '',
  loginImageUrl: '',
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
  loginImageUrl: server.login_image_url,
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
  login_image_url: config.loginImageUrl,
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

const notifyBrandingUpdated = () => {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('branding-updated'));
  }
};

export const applyBrandingToDocument = () => {
  if (typeof document === 'undefined') return;
  document.title = branding.productName;
  const appName = document.querySelector<HTMLMetaElement>('meta[name="application-name"]');
  if (appName) appName.content = branding.productName;
  const author = document.querySelector<HTMLMetaElement>('meta[name="author"]');
  if (author) author.content = branding.companyName;

  document.querySelectorAll<HTMLLinkElement>('link[rel*="icon"]').forEach((link) => {
    if (!originalFavicons.has(link)) originalFavicons.set(link, link.href);
    link.href = branding.faviconUrl || originalFavicons.get(link) || link.href;
  });

  if (branding.primaryColor) {
    document.documentElement.style.setProperty('--brand-primary', branding.primaryColor);
  } else {
    document.documentElement.style.removeProperty('--brand-primary');
  }
};

export const applyBranding = (next: BrandingConfig) => {
  Object.assign(branding, next);
  applyBrandingToDocument();
  notifyBrandingUpdated();
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
    // Core is authoritative after a successful fetch. Browser-local data is only a
    // startup fallback for deployments where Core is temporarily unavailable.
    clearLocalBrandingOverride();
    applyBranding({
      ...brandingDefaults,
      ...deploymentBranding(),
      ...server,
    });
  } catch {
    // Keep deployment/local fallback values when Core is unavailable during startup.
  }
  return branding;
};

// Retained for callers that explicitly want a browser-local fallback. Server-backed
// settings should use applyBranding() instead.
export const saveBranding = (next: BrandingConfig) => {
  Object.assign(branding, next);
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  }
  applyBrandingToDocument();
  notifyBrandingUpdated();
};

export const clearLocalBrandingOverride = () => {
  if (typeof window !== 'undefined') window.localStorage.removeItem(STORAGE_KEY);
};

export const resetBranding = () => {
  const next: BrandingConfig = {
    ...brandingDefaults,
    ...deploymentBranding(),
  };
  clearLocalBrandingOverride();
  applyBranding(next);
  return next;
};
