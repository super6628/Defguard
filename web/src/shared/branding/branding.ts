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
  instance_name?: string;
  main_logo_url?: string;
  nav_logo_url?: string;
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
    const response = await fetch('/api/v1/settings_essentials', {
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) return branding;
    const server = (await response.json()) as ServerBranding;
    const local = readSavedBranding();
    Object.assign(branding, {
      ...brandingDefaults,
      ...deploymentBranding(),
      ...(server.instance_name ? { productName: server.instance_name } : {}),
      ...(server.main_logo_url ? { logoUrl: server.main_logo_url } : {}),
      ...(server.nav_logo_url ? { navLogoUrl: server.nav_logo_url } : {}),
      ...local,
    });
    applyBrandingToDocument();
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

export const resetBranding = () => {
  const next: BrandingConfig = {
    ...brandingDefaults,
    ...deploymentBranding(),
  };
  Object.assign(branding, next);
  if (typeof window !== 'undefined') window.localStorage.removeItem(STORAGE_KEY);
  applyBrandingToDocument();
  window.dispatchEvent(new CustomEvent('branding-updated'));
  return next;
};
