export type BrandingConfig = {
  companyName: string;
  productName: string;
  shortName: string;
  copyrightName: string;
  supportEmail: string;
  supportUrl: string;
  documentationUrl: string;
  logoUrl: string;
  logoDarkUrl: string;
  faviconUrl: string;
  primaryColor: string;
  loginTitle: string;
  loginSubtitle: string;
  setupTitle: string;
  setupSubtitle: string;
  setupButtonText: string;
};

const defaults: BrandingConfig = {
  companyName: 'S-Metric',
  productName: 'S-Metric Secure',
  shortName: 'S-Metric',
  copyrightName: 'S-Metric',
  supportEmail: '',
  supportUrl: '',
  documentationUrl: 'https://docs.defguard.net/',
  logoUrl: '',
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

export const branding: BrandingConfig = {
  ...defaults,
  ...(typeof window !== 'undefined' ? window.__WHITE_LABEL__ : {}),
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
  }
};
