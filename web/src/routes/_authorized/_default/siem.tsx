import { createFileRoute } from '@tanstack/react-router';
import { SiemPage } from '../../../pages/SiemPage/SiemPage';

// The generated route tree is refreshed by the TanStack Vite plugin during builds.
// `as never` keeps a clean `tsc -b` checkout valid before that generated file is refreshed.
export const Route = createFileRoute('/_authorized/_default/siem' as never)({
  component: SiemPage,
});
