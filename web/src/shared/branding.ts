export type BrandConfig = {
  productName: string;
  companyName: string;
  logoUrl?: string;
  compactLogoUrl?: string;
  faviconUrl?: string;
  supportEmail?: string;
  documentationUrl?: string;
  websiteUrl?: string;
  bugReportUrl?: string;
  featureRequestUrl?: string;
  supportTicketUrl?: string;
  scheduleCallUrl?: string;
};

const readEnv = (name: string): string | undefined => {
  const value = import.meta.env[name];
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
};

/**
 * Customer-facing brand configuration.
 *
 * S-Metric Secure is the default distribution brand. Deployments can override
 * these values at build time without changing application source code.
 * Internal Defguard-compatible API, package and protocol identifiers are kept
 * separate from this configuration intentionally.
 */
export const brandConfig: BrandConfig = {
  productName: readEnv('VITE_BRAND_PRODUCT_NAME') ?? 'S-Metric Secure',
  companyName: readEnv('VITE_BRAND_COMPANY_NAME') ?? 'S-Metric',
  logoUrl: readEnv('VITE_BRAND_LOGO_URL'),
  compactLogoUrl: readEnv('VITE_BRAND_COMPACT_LOGO_URL'),
  faviconUrl: readEnv('VITE_BRAND_FAVICON_URL'),
  supportEmail: readEnv('VITE_BRAND_SUPPORT_EMAIL'),
  documentationUrl: readEnv('VITE_BRAND_DOCUMENTATION_URL'),
  websiteUrl: readEnv('VITE_BRAND_WEBSITE_URL'),
  bugReportUrl: readEnv('VITE_BRAND_BUG_REPORT_URL'),
  featureRequestUrl: readEnv('VITE_BRAND_FEATURE_REQUEST_URL'),
  supportTicketUrl: readEnv('VITE_BRAND_SUPPORT_TICKET_URL'),
  scheduleCallUrl: readEnv('VITE_BRAND_SCHEDULE_CALL_URL'),
};

/**
 * Mapping for customer-visible legacy terminology.
 *
 * Keep protocol names, package names, API fields, environment variables,
 * database identifiers and compatibility strings unchanged. This mapping is
 * only for text presented to users in the web application.
 */
export const brandTerminology = {
  Defguard: brandConfig.productName,
  'Defguard instance': `${brandConfig.productName} instance`,
  'Defguard Core': `${brandConfig.productName} Core`,
  "Defguard's internal CA": `${brandConfig.productName}'s internal CA`,
  'Defguard internal CA': `${brandConfig.productName} internal CA`,
} as const;

export type LegacyBrandTerm = keyof typeof brandTerminology;

export const mapCustomerFacingBrandTerm = (term: LegacyBrandTerm): string => brandTerminology[term];
