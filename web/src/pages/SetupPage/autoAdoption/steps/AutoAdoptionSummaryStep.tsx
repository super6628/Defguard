import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { m } from '../../../../paraglide/messages';
import api from '../../../../shared/api/api';
import { branding } from '../../../../shared/branding/branding';
import {
  WizardStepSummary,
  type WizardStepSummaryRecommendation,
} from '../../../../shared/components/wizard-steps/WizardStepSummary/WizardStepSummary';
import { Snackbar } from '../../../../shared/defguard-ui/providers/snackbar/snackbar';
import CommunityIcon from '../../assets/community.png';
import FileIcon from '../../assets/file-icon.png';
import ShieldIcon from '../../assets/shield.png';
import { useAutoAdoptionSetupWizardStore } from '../useAutoAdoptionSetupWizardStore';

export const AutoAdoptionSummaryStep = () => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const wireguardPort = useAutoAdoptionSetupWizardStore((s) => s.vpn_wireguard_port);
  const defguardUrl = useAutoAdoptionSetupWizardStore((s) => s.defguard_url);

  const { mutateAsync: finishSetup } = useMutation({
    mutationKey: ['finish-setup'],
    mutationFn: api.initial_setup.finishSetup,
    meta: {
      invalidate: ['settings_essentials'],
    },
  });

  const handleGoToDefguard = async () => {
    try {
      setIsSubmitting(true);
      useAutoAdoptionSetupWizardStore.setState({ isFinishing: true });
      await finishSetup();
      const base = defguardUrl ? defguardUrl.replace(/\/$/, '') : window.location.origin;
      window.onbeforeunload = null;
      await new Promise((r) => setTimeout(r, 2000));
      useAutoAdoptionSetupWizardStore.getState().reset();
      window.location.replace(`${base}/auth/login`);
    } catch (error) {
      console.error(m.initial_setup_auto_adoption_summary_error_finish_console(), error);
      useAutoAdoptionSetupWizardStore.setState({ isFinishing: false });
      Snackbar.error(m.initial_setup_confirmation_error_finish_failed());
      setIsSubmitting(false);
    }
  };

  const recommendations: WizardStepSummaryRecommendation[] = [];

  if (branding.documentationUrl) {
    recommendations.push({
      iconSrc: FileIcon,
      iconAlt: m.initial_setup_auto_adoption_summary_docs_icon_alt(),
      kicker: m.initial_setup_auto_adoption_summary_docs_kicker(),
      title: m.initial_setup_auto_adoption_summary_docs_title(),
      buttonText: m.initial_setup_auto_adoption_summary_docs_button(),
      onButtonClick: () => window.open(branding.documentationUrl, '_blank'),
    });
  }

  if (branding.supportUrl) {
    recommendations.push({
      iconSrc: CommunityIcon,
      iconAlt: m.initial_setup_auto_adoption_summary_community_icon_alt(),
      kicker: m.initial_setup_auto_adoption_summary_community_kicker(),
      title: m.initial_setup_auto_adoption_summary_community_title(),
      buttonText: m.initial_setup_auto_adoption_summary_community_button(),
      onButtonClick: () => window.open(branding.supportUrl, '_blank'),
    });
  }

  if (branding.supportEmail) {
    recommendations.push({
      iconSrc: ShieldIcon,
      iconAlt: m.initial_setup_auto_adoption_summary_support_icon_alt(),
      kicker: m.initial_setup_auto_adoption_summary_support_kicker(),
      title: m.initial_setup_auto_adoption_summary_support_title(),
      buttonText: m.initial_setup_auto_adoption_summary_support_button(),
      onButtonClick: () => window.location.assign(`mailto:${branding.supportEmail}`),
    });
  }

  return (
    <WizardStepSummary
      thankYouText={`Thank you for choosing ${branding.productName}!`}
      noteText={m.initial_setup_auto_adoption_summary_note()}
      ports={[
        m.initial_setup_auto_adoption_summary_ports_http_https(),
        m.initial_setup_auto_adoption_summary_ports_wireguard({
          port: wireguardPort,
        }),
      ]}
      encourageText={m.initial_setup_auto_adoption_summary_encourage()}
      recommendations={recommendations}
      submitButtonText={`Go to ${branding.productName}`}
      onSubmit={handleGoToDefguard}
      submitLoading={isSubmitting}
    />
  );
};
