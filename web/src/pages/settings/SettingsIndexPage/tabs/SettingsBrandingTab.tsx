import { useEffect, useState } from 'react';
import {
  type BrandingConfig,
  applyBranding,
  branding,
  clearLocalBrandingOverride,
  hydrateBrandingFromServer,
  resetBranding,
  toServerBranding,
} from '../../../../shared/branding/branding';

const fields: Array<{ key: keyof BrandingConfig; label: string; placeholder?: string }> = [
  { key: 'companyName', label: 'Company name' },
  { key: 'productName', label: 'Product name' },
  { key: 'shortName', label: 'Short name' },
  { key: 'copyrightName', label: 'Copyright name' },
  { key: 'supportEmail', label: 'Support email' },
  { key: 'supportUrl', label: 'Support URL' },
  { key: 'documentationUrl', label: 'Documentation URL' },
  { key: 'logoUrl', label: 'Main / login logo URL', placeholder: '/svg/logo.svg' },
  { key: 'navLogoUrl', label: 'Navigation logo URL', placeholder: '/svg/nav-logo.svg' },
  { key: 'logoDarkUrl', label: 'Dark logo URL', placeholder: '/branding/logo-dark.svg' },
  { key: 'faviconUrl', label: 'Favicon URL', placeholder: '/branding/favicon.ico' },
  { key: 'primaryColor', label: 'Primary color', placeholder: '#3961DB' },
  { key: 'loginTitle', label: 'Login title' },
  { key: 'loginSubtitle', label: 'Login subtitle' },
  { key: 'setupTitle', label: 'Setup title' },
  { key: 'setupSubtitle', label: 'Setup subtitle' },
  { key: 'setupButtonText', label: 'Setup button text' },
];

export const SettingsBrandingTab = () => {
  const [form, setForm] = useState<BrandingConfig>({ ...branding });
  const [status, setStatus] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void hydrateBrandingFromServer().then((current) => setForm({ ...current }));
  }, []);

  const update = (key: keyof BrandingConfig, value: string) => {
    setStatus('');
    setForm((current) => ({ ...current, [key]: value }));
  };

  const onSave = async () => {
    setSaving(true);
    setStatus('');
    try {
      const response = await fetch('/api/v1/branding', {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(toServerBranding(form)),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Branding save failed with ${response.status}`);
      }
      clearLocalBrandingOverride();
      applyBranding(form);
      setStatus('Branding saved to Core. The complete configuration is now shared across browsers.');
    } catch (error) {
      setStatus(error instanceof Error ? `Core save failed: ${error.message}` : 'Core save failed.');
    } finally {
      setSaving(false);
    }
  };

  const onReset = async () => {
    setSaving(true);
    setStatus('');
    try {
      const response = await fetch('/api/v1/branding', {
        method: 'DELETE',
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Branding reset failed with ${response.status}`);
      }
      clearLocalBrandingOverride();
      resetBranding();
      await hydrateBrandingFromServer();
      setForm({ ...branding });
      setStatus('Branding reset to the Core defaults.');
    } catch (error) {
      setStatus(error instanceof Error ? `Core reset failed: ${error.message}` : 'Core reset failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ paddingTop: 24, maxWidth: 980 }}>
      <h2 style={{ marginBottom: 8 }}>White-label branding</h2>
      <p style={{ marginBottom: 24 }}>
        This configuration is stored in Core and shared across browsers. Runtime branding.js values remain a fallback when Core is unavailable.
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(280px, 0.8fr)', gap: 32 }}>
        <div style={{ display: 'grid', gap: 16 }}>
          {fields.map(({ key, label, placeholder }) => (
            <label key={key} style={{ display: 'grid', gap: 6 }}>
              <span style={{ fontWeight: 600 }}>{label}</span>
              <input
                value={form[key]}
                placeholder={placeholder}
                onChange={(event) => update(key, event.target.value)}
                style={{ padding: '10px 12px', border: '1px solid #d1d5db', borderRadius: 6 }}
              />
            </label>
          ))}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <button type="button" disabled={saving} onClick={() => void onSave()} style={{ padding: '10px 18px', cursor: 'pointer' }}>
              {saving ? 'Saving…' : 'Save branding'}
            </button>
            <button type="button" disabled={saving} onClick={() => void onReset()} style={{ padding: '10px 18px', cursor: 'pointer' }}>
              Reset branding
            </button>
            {status && <span>{status}</span>}
          </div>
        </div>
        <aside style={{ border: '1px solid #e5e7eb', borderRadius: 10, padding: 24, alignSelf: 'start' }}>
          <div style={{ fontSize: 12, textTransform: 'uppercase', opacity: 0.65, marginBottom: 16 }}>Live preview</div>
          {form.logoUrl ? <img src={form.logoUrl} alt={form.productName} style={{ maxWidth: '100%', maxHeight: 60 }} /> : <div style={{ fontSize: 22, fontWeight: 700 }}>{form.shortName || form.companyName}</div>}
          <h3 style={{ marginTop: 28 }}>{form.loginTitle || `Welcome to ${form.productName}`}</h3>
          <p>{form.loginSubtitle || 'Secure remote network access'}</p>
          <button type="button" style={{ marginTop: 18, padding: '10px 18px', borderRadius: 6, border: 0, background: form.primaryColor || '#3961DB', color: '#fff' }}>Sign in</button>
          <hr style={{ margin: '28px 0 16px', border: 0, borderTop: '1px solid #e5e7eb' }} />
          <small>Copyright © {new Date().getFullYear()} {form.copyrightName}</small>
        </aside>
      </div>
    </div>
  );
};
