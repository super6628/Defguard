import { createFileRoute } from '@tanstack/react-router';
import { SiemPage } from '../../../pages/SiemPage/SiemPage';

export const Route = createFileRoute('/_authorized/_default/siem')({
  component: SiemPage,
});
