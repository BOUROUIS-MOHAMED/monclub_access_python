export type RenewalPlan = {
  id: number | string;
  title?: string;
  price?: number | string;
  successor_plan_id?: number | string | null;
};

export function renewalPlanChoice(plans: RenewalPlan[], membershipId?: number | string) {
  const current = plans.find((plan) => String(plan.id) === String(membershipId));
  const successor = current?.successor_plan_id == null ? undefined
    : plans.find((plan) => String(plan.id) === String(current.successor_plan_id));
  if (successor) {
    return {
      plan: successor,
      note: `Ancienne formule « ${current?.title || `Abonnement ${current?.id}`} » rangée : renouvellement sur « ${successor.title || `Abonnement ${successor.id}`} ».`,
    };
  }
  return { plan: current && current.successor_plan_id == null ? current : plans[0], note: null };
}
