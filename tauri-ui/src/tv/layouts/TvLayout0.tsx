/**
 * TvLayout0 — Cool Layout (layoutPresetId = 0)
 * Thin wrapper around MonClubTvCoolScreenLayout.
 */

import MonClubTvCoolScreenLayout, { type SmartDashboardPageProps } from './MonClubTvCoolScreenLayout';

export type TvLayout0Props = SmartDashboardPageProps;

export default function TvLayout0(props: TvLayout0Props) {
  return <MonClubTvCoolScreenLayout {...props} />;
}
