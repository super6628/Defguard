import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import 'react-loading-skeleton/dist/skeleton.css';
// keep this as last style import
import './shared/defguard-ui/scss/index.scss';
import { App } from './app/App.tsx';
import { brandConfig } from './shared/branding.ts';

const applicationNameMeta = document.querySelector<HTMLMetaElement>('meta[name="application-name"]');
const authorMeta = document.querySelector<HTMLMetaElement>('meta[name="author"]');

document.title = brandConfig.productName;
applicationNameMeta?.setAttribute('content', brandConfig.productName);
authorMeta?.setAttribute('content', brandConfig.companyName);

if (brandConfig.faviconUrl) {
  for (const favicon of document.querySelectorAll<HTMLLinkElement>('link[rel*="icon"]')) {
    favicon.href = brandConfig.faviconUrl;
  }
}

// biome-ignore lint/style/noNonNullAssertion: always there
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
