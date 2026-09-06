import { branding } from '../../branding/branding';
import { ThemeVariable } from '../../defguard-ui/types';

export const LoginPageLogo = () => {
  const customLogo = branding.logoDarkUrl || branding.logoUrl;
  if (customLogo) {
    return (
      <img
        src={customLogo}
        alt={branding.productName}
        className="login-logo"
        style={{ maxWidth: 220, maxHeight: 56, objectFit: 'contain' }}
      />
    );
  }

  const shortName = branding.shortName.trim();
  const productName = branding.productName.trim();
  const productSuffix = productName.toLowerCase().startsWith(shortName.toLowerCase())
    ? productName.slice(shortName.length).trim()
    : productName;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="220"
      height="40"
      viewBox="0 0 220 40"
      fill="none"
      className="login-logo"
      role="img"
      aria-label={branding.productName}
    >
      <rect x="1" y="4" width="32" height="32" rx="8" style={{ fill: ThemeVariable.BgAction }} />
      <path
        d="M24.2 13.5C22.3 12.1 20 11.4 17.5 11.4C13.3 11.4 10.4 13.5 10.4 16.5C10.4 19.5 12.8 20.6 17 21.4C20 22 21.1 22.5 21.1 23.7C21.1 25 19.7 25.8 17.5 25.8C15 25.8 12.6 25 10.6 23.3L8.9 26C11.2 28 14.2 29 17.4 29C21.8 29 24.8 27 24.8 23.4C24.8 20.3 22.3 19.2 18.1 18.4C15.1 17.8 14 17.3 14 16.2C14 15 15.3 14.3 17.4 14.3C19.4 14.3 21.2 14.9 22.8 16.1L24.2 13.5Z"
        fill="white"
      />
      <text x="44" y="19" fontFamily="Inter, system-ui, sans-serif" fontSize="16" fontWeight="700" fill="#191A1C">
        {(shortName || productName).toUpperCase()}
      </text>
      {productSuffix && productSuffix.toLowerCase() !== shortName.toLowerCase() && (
        <text x="44" y="33" fontFamily="Inter, system-ui, sans-serif" fontSize="12" fontWeight="500" fill="#6B7280">
          {productSuffix.toUpperCase()}
        </text>
      )}
    </svg>
  );
};
