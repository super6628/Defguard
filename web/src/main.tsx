import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import 'react-loading-skeleton/dist/skeleton.css';
// keep this as last style import
import './shared/defguard-ui/scss/index.scss';
import { App } from './app/App.tsx';
import {
  applyBrandingToDocument,
  hydrateBrandingFromServer,
} from './shared/branding/branding.ts';

const bootstrap = async () => {
  applyBrandingToDocument();
  await hydrateBrandingFromServer();

  // biome-ignore lint/style/noNonNullAssertion: always there
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
};

void bootstrap();
