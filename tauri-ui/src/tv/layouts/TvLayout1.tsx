/**
 * TvLayout1 — Smart Layout (layoutPresetId = 1)
 * Thin wrapper around MonClubTvSmartScreenLayout.
 */

import MonClubTvSmartScreenLayout, { type SmartHomeDashboardPageProps } from './MonClubTvSmartScreenLayout';

export type TvLayout1Props = SmartHomeDashboardPageProps;

export default function TvLayout1(props: TvLayout1Props) {
  return <MonClubTvSmartScreenLayout {...props} />;
}
