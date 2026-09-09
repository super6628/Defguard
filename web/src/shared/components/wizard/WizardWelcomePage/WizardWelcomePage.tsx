import './style.scss';
import clsx from 'clsx';
import dayjs from 'dayjs';
import { m } from '../../../../paraglide/messages';
import { brandConfig } from '../../../branding';
import { AppText } from '../../../defguard-ui/components/AppText/AppText';
import { ExternalLink } from '../../../defguard-ui/components/ExternalLink/ExternalLink';
import { SizedBox } from '../../../defguard-ui/components/SizedBox/SizedBox';
import { TextStyle, ThemeSpacing, ThemeVariable } from '../../../defguard-ui/types';
import { isPresent } from '../../../defguard-ui/utils/isPresent';
import type { WizardWelcomePageConfig } from '../types';
import { WizardTop } from '../WizardTop/WizardTop';
import fileIcon from './assets/file_icon.png';
import defaultGlobe from './assets/world_map.png';

type Props = WizardWelcomePageConfig;

export const WizardWelcomePage = ({
  title,
  subtitle,
  content,
  media,
  containerProps,
  docsLink = brandConfig.documentationUrl,
  docsText = m.initial_setup_wizard_welcome_docs_description(),
  displayDocs = true,
  onClose,
}: Props) => {
  const showDocs = displayDocs && isPresent(docsLink);

  return (
    <div
      {...containerProps}
      className={clsx('wizard-welcome-page', containerProps?.className)}
    >
      <WizardTop onClick={onClose} />
      <SizedBox height={ThemeSpacing.Xl4} />
      <div className="content">
        <div className="main-track">
          <div className="top-content">
            <h1>{title}</h1>
            <SizedBox height={ThemeSpacing.Lg} />
            <AppText font={TextStyle.TBodyPrimary400} color={ThemeVariable.FgFaded}>
              {subtitle}
            </AppText>
            <div className="left">{content}</div>
          </div>
          {showDocs && (
            <div id="docs-card">
              <div className="image-track">
                <img src={fileIcon} alt={m.initial_setup_wizard_welcome_docs_alt()} />
              </div>

              <div className="content">
                <p>{docsText}</p>
                <div>
                  <ExternalLink href={docsLink}>
                    {m.initial_setup_wizard_welcome_docs_link()}
                  </ExternalLink>
                </div>
              </div>
            </div>
          )}
        </div>
        <div className="media-track">
          {media}
          {!isPresent(media) && (
            <img src={defaultGlobe} alt="default globe" id="default-globe-media-image" />
          )}
        </div>
      </div>
      <div className="footer">
        <p>{m.footer_copyright({ year: dayjs().year() })}</p>
        <p>{brandConfig.productName}</p>
      </div>
    </div>
  );
};
