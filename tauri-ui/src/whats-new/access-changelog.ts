// Add releases newest version first, using the installed app version and at most
// 4 short, gym-staff-facing items per release. Supply both French and English.
// Leave this empty until the owner approves items for an Access release.
export const ACCESS_CHANGELOG: {
  version: string;
  items: { category: "new" | "perf" | "fix" | "acc" | "sec"; fr: string; en: string }[];
}[] = [
  {
    version: "1.4.39",
    items: [
      {
        category: "acc",
        fr: "Limites d’entrées : le PC retire des tourniquets les membres qui ont atteint leur limite et les remet à la réinitialisation ; le QR affiche « Limite d’entrées atteinte ».",
        en: "Entry limits: the PC takes members who reached their limit off the turnstiles and puts them back at the reset; the QR shows “Entry limit reached”.",
      },
    ],
  },
];
