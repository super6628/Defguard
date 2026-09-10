import { useMutation } from '@tanstack/react-query';
import type { AxiosError } from 'axios';
import z from 'zod';
import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import { getApiErrorMessage } from '../../../../shared/api/apiErrorMessages';
import type { ApiError } from '../../../../shared/api/types';
import { branding } from '../../../../shared/branding/branding';
import { Controls } from '../../../../shared/components/Controls/Controls';
import { WizardCard } from '../../../../shared/components/wizard/WizardCard/WizardCard';
import { Button } from '../../../../shared/defguard-ui/components/Button/Button';
import { Divider } from '../../../../shared/defguard-ui/components/Divider/Divider';
import { Helper } from '../../../../shared/defguard-ui/components/Helper/Helper';
import { Radio } from '../../../../shared/defguard-ui/components/Radio/Radio';
import { SizedBox } from '../../../../shared/defguard-ui/components/SizedBox/SizedBox';
import { Snackbar } from '../../../../shared/defguard-ui/providers/snackbar/snackbar';
import { ThemeSpacing } from '../../../../shared/defguard-ui/types';
import { useAppForm } from '../../../../shared/form';
import { formChangeLogic } from '../../../../shared/formLogic';
import {
  correctUrlProtocol,
  ensureUrlScheme,
  isValidDefguardUrl,
} from '../../../../shared/utils/defguardUrl';
import type { InternalSslType } from '../../autoAdoption/types';
import '../../autoAdoption/steps/style.scss';
import { SetupPageStep } from '../types';
import { useSetupWizardStore } from '../useSetupWizardStore';

export const SetupInternalUrlSettingsStep = () => {
  const setActiveStep = useSetupWizardStore((s) => s.setActiveStep);
  const storedUrl = useSetupWizardStore((s) => s.defguard_url);
  const storedSslType = useSetupWizardStore((s) => s.internal_ssl_type);

  const formSchema = z.object({
    defguard_url: z
      .string({
        error: `${branding.productName} URL is required`,
      })
      .overwrite(ensureUrlScheme)
      .min(1, `${branding.productName} URL is required`)
      .url(m.initial_setup_general_config_error_invalid_url())
      .refine(isValidDefguardUrl, `${branding.productName} URL must use a hostname, not an IP address`),
    ssl_type: z.custom<InternalSslType>(),
    cert_pem_file: z.custom<File | null>().nullable(),
    key_pem_file: z.custom<File | null>().nullable(),
  });

  const { mutate, isPending } = useMutation({
    mutationFn: api.initial_setup.setAutoAdoptionInternalUrlSettings,
    meta: { invalidate: [['info'], ['internal_ssl_info']] },
    onSuccess: (response) => {
      useSetupWizardStore.setState({
        internal_ssl_type: form.getFieldValue('ssl_type'),
        internal_ssl_cert_info: response.data.cert_info ?? null,
      });
      setActiveStep(SetupPageStep.InternalUrlSslConfig);
    },
    onError: (error: AxiosError<ApiError>) => {
      const code = error.response?.data?.code;
      const fallback =
        error.response?.data?.msg ?? m.initial_setup_general_config_error_save_failed();
      if (code) {
        Snackbar.error(getApiErrorMessage(code, fallback));
      } else {
        Snackbar.error(fallback);
      }
      console.error('Failed to save internal URL settings:', error);
    },
  });

  const form = useAppForm({
    defaultValues: {
      defguard_url: storedUrl,
      ssl_type: (storedSslType ?? 'none') as InternalSslType,
      cert_pem_file: null as File | null,
      key_pem_file: null as File | null,
    },
    validationLogic: formChangeLogic,
    validators: { onSubmit: formSchema, onChange: formSchema },
    onSubmit: async ({ value }) => {
      if (
        value.ssl_type === 'own_cert' &&
        (!value.cert_pem_file || !value.key_pem_file)
      ) {
        Snackbar.error(
          m.initial_setup_auto_adoption_internal_url_settings_upload_files_required(),
        );
        return;
      }
      const correctedUrl = correctUrlProtocol(value.defguard_url, value.ssl_type);
      useSetupWizardStore.setState({
        defguard_url: correctedUrl,
      });
      mutate({
        defguard_url: correctedUrl,
        ssl_type: value.ssl_type,
        cert_pem: value.cert_pem_file ? await value.cert_pem_file.text() : undefined,
        key_pem: value.key_pem_file ? await value.key_pem_file.text() : undefined,
      });
    },
  });

  return (
    <WizardCard>
      <form
        onSubmit={(e) => {
          e.stopPropagation();
          e.preventDefault();
          form.handleSubmit();
        }}
      >
        <form.AppForm>
          <p>
            Enter the URL for {branding.productName}, including the port if needed. It must be
            reachable on your internal or VPN network and should not be exposed directly to the
            internet. Once setup is complete, you'll be redirected there automatically.
          </p>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.AppField name="defguard_url">
            {(field) => (
              <field.FormInput
                required
                label={`${branding.productName} URL`}
                helper={m.initial_setup_general_config_helper_defguard_url()}
                type="text"
              />
            )}
          </form.AppField>
          <SizedBox height={ThemeSpacing.Xl} />
          <form.Subscribe selector={(s) => s.values.ssl_type}>
            {(sslType) => (
              <div className="ssl-options">
                <div className="ssl-option-row">
                  <Radio
                    text={m.initial_setup_auto_adoption_internal_url_settings_ssl_option_none()}
                    active={sslType === 'none'}
                    onClick={() => form.setFieldValue('ssl_type', 'none')}
                  />
                  <Helper>
                    {m.initial_setup_auto_adoption_internal_url_settings_ssl_option_none_help()}
                  </Helper>
                </div>
                <SizedBox height={ThemeSpacing.Md} />
                <div className="ssl-option-row">
                  <Radio
                    text="Generate certificates using the internal CA"
                    active={sslType === 'defguard_ca'}
                    onClick={() => form.setFieldValue('ssl_type', 'defguard_ca')}
                  />
                  <Helper>
                    {branding.productName} will generate and manage a certificate signed by its
                    internal CA.
                  </Helper>
                </div>
                <SizedBox height={ThemeSpacing.Md} />
                <div className="ssl-option-row">
                  <Radio
                    text={m.initial_setup_auto_adoption_internal_url_settings_ssl_option_own_cert()}
                    active={sslType === 'own_cert'}
                    onClick={() => form.setFieldValue('ssl_type', 'own_cert')}
                  />
                  <Helper>
                    {m.initial_setup_auto_adoption_internal_url_settings_ssl_option_own_cert_help()}
                  </Helper>
                </div>
                {sslType === 'own_cert' && (
                  <div className="cert-upload-section">
                    <SizedBox height={ThemeSpacing.Lg} />
                    <form.AppField name="cert_pem_file">
                      {(field) => (
                        <field.FormUploadField
                          acceptedExtensions={['.pem', '.crt', '.cer']}
                          title={m.initial_setup_auto_adoption_internal_url_settings_upload_cert_button()}
                        />
                      )}
                    </form.AppField>
                    <SizedBox height={ThemeSpacing.Md} />
                    <form.AppField name="key_pem_file">
                      {(field) => (
                        <field.FormUploadField
                          acceptedExtensions={['.pem', '.key']}
                          title={m.initial_setup_auto_adoption_internal_url_settings_upload_key_button()}
                        />
                      )}
                    </form.AppField>
                  </div>
                )}
              </div>
            )}
          </form.Subscribe>
        </form.AppForm>
      </form>
      <SizedBox height={ThemeSpacing.Xl3} />
      <Divider />
      <Controls>
        <div className="right">
          <Button
            text={m.initial_setup_controls_continue()}
            onClick={form.handleSubmit}
            loading={isPending}
          />
        </div>
      </Controls>
    </WizardCard>
  );
};
