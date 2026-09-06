import { OpenIdProviderKind, type OpenIdProviderKindValue } from './api/types';
import { brandConfig } from './branding';

export const externalLink = {
  defguard: {
    docs: brandConfig.documentationUrl ?? 'https://docs.defguard.net',
    pricing: brandConfig.pricingUrl ?? 'https://defguard.net/pricing',
    download: brandConfig.downloadUrl ?? 'https://defguard.net/download',
    sales: brandConfig.salesUrl ?? 'https://defguard.net/contact/',
    scheduleCall:
      brandConfig.scheduleCallUrl ??
      'https://docs.google.com/forms/d/e/1FAIpQLSdKr1NXH1DlQuAF5oQWvT7Zri5yPQ3txvwz3qgtb1n9FtKTgw/viewform',
    openTicket:
      brandConfig.supportTicketUrl ?? 'https://support.defguard.net/support/auth/login/customer/?customer_id=',
  },
  github: {
    bugReport:
      brandConfig.bugReportUrl ?? 'https://github.com/DefGuard/defguard/issues/new?template=02-bug.yml',
    featureRequest:
      brandConfig.featureRequestUrl ??
      'https://github.com/DefGuard/defguard/issues/new?template=01-feature-request.yml',
  },
  client: {
    desktop: {
      linux: {
        arch: 'https://aur.archlinux.org/packages/defguard-client',
      },
    },
    mobile: {
      apple: 'https://apps.apple.com/us/app/defguard-vpn-client/id6748068630',
      google: 'https://play.google.com/store/apps/details?id=net.defguard.mobile',
    },
  },
} as const;

export const externalProviderName: Record<OpenIdProviderKindValue, string> = {
  Custom: 'Custom provider',
  Google: 'Google',
  JumpCloud: 'JumpCloud',
  Microsoft: 'Microsoft',
  Okta: 'Okta',
  Zitadel: 'Zitadel',
};

export const supportedSyncProviders: Set<OpenIdProviderKindValue> = new Set([
  OpenIdProviderKind.Google,
  OpenIdProviderKind.Microsoft,
  OpenIdProviderKind.Okta,
  OpenIdProviderKind.JumpCloud,
]);

export const googleProviderBaseUrl = 'https://accounts.google.com';

export type JumpCloudRegion = 'us' | 'eu' | 'in';

export const jumpcloudBaseUrls: Record<JumpCloudRegion, string> = {
  us: 'https://oauth.id.jumpcloud.com/',
  eu: 'https://oauth.id.eu.jumpcloud.com/',
  in: 'https://oauth.id.in.jumpcloud.com/',
};

export const detectJumpcloudRegion = (baseUrl: string | undefined): JumpCloudRegion => {
  if (baseUrl?.includes('eu.jumpcloud')) {
    return 'eu';
  }
  if (baseUrl?.includes('in.jumpcloud')) {
    return 'in';
  }
  return 'us';
};

export const licenseGracePeriodDays = 14;

export const edgeDefaultGrpcPort = 50051;

export const gatewayDefaultGrpcPort = 50066;

export const DISMISSED_UPDATE_KEY = 'dismissed-update-version';
