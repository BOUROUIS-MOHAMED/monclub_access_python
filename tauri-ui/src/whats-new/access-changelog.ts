// Add releases newest version first, using the installed app version and at most
// 4 short, gym-staff-facing items per release. Supply both French and English.
// Leave this empty until the owner approves items for an Access release.
export const ACCESS_CHANGELOG: {
  version: string;
  items: { category: "new" | "perf" | "fix" | "acc" | "sec"; fr: string; en: string }[];
}[] = [];
