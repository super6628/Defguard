import './style.scss';
import { useNavigate } from '@tanstack/react-router';
import { type ReactNode, useMemo } from 'react';
import { m } from '../../paraglide/messages';
import { branding } from '../../shared/branding/branding';
import { Controls } from '../../shared/components/Controls/Controls';
import type { WizardPageStep } from '../../shared/components/wizard/types';
import { WizardCoverImage } from '../../shared/components/wizard/WizardCoverImage/WizardCoverImage';
import { WizardPage } from '../../shared/components/wizard/WizardPage/WizardPage';
import { Button } from '../../shared/defguard-ui