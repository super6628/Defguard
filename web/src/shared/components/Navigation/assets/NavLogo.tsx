import { brandConfig } from '../../../branding';
import { ThemeVariable } from '../../../defguard-ui/types';

export const NavLogo = () => {
  if (brandConfig.logoUrl) {
    return (
      <img
        src={brandConfig.logoUrl}
        alt={brandConfig.productName}
        style={{ width: 172, height: 28, objectFit: 'contain', objectPosition: 'left center' }}
      />
    );
  }

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="172"
      height="28"
      viewBox="0 0 172 28"
      fill="none"
      role="img"
      aria-label={brandConfig.productName}
    >
      <rect x="1" y="1" width="26" height="26" rx="7" style={{ fill: ThemeVariable.BgAction }} />
      <path
        d="M19.8 8.7C18.2 7.6 16.3 7 14.2 7C10.7 7 8.3 8.7 8.3 11.2C8.3 13.7 10.3 14.6 13.8 15.3C16.3 15.8 17.2 16.2 17.2 17.2C17.2 18.3 16 19 14.2 19C12.1 19 10.1 18.3 8.4 16.9L7 19.1C8.9 20.7 11.4 21.5 14.1 21.5C17.8 21.5 20.3 19.8 20.3 17C20.3 14.4 18.2 13.5 14.7 12.8C12.2 12.3 11.3 11.9 11.3 11C11.3 10 12.4 9.4 14.1 9.4C15.8 9.4 17.3 9.9 18.6 10.9L19.8 8.7Z"
        fill="white"
      />
      <text
        x="35"
        y="13"
        fontFamily="Inter, system-ui, sans-serif"
        fontSize="12"
        fontWeight="700"
        style={{ fill: ThemeVariable.BgInverted }}
      >
        {brandConfig.companyName.toUpperCase()}
      </text>
      <text
        x="35"
        y="24"
        fontFamily="Inter, system-ui, sans-serif"
        fontSize="10"
        fontWeight="500"
        style={{ fill: ThemeVariable.FgFaded }}
      >
        {brandConfig.productName.replace(new RegExp(`^${brandConfig.companyName}\\s*`, 'i'), '').toUpperCase() || 'SECURE'}
      </text>
    </svg>
  );
};
