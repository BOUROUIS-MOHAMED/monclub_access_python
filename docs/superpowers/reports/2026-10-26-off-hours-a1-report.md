# A1 — MonClub Access 1.4.38

Version **1.4.38**. Branche `claude/off-hours-a1`, base `master 26a7945`.
A1 terminé ; arrêt avant D1. Aucun push, merge, build de release, lancement réel de l'application ou accès à un dispositif / aux données du club.
La copie pointée du plan se trouve dans `../plans/2026-10-24-plan-off-hours-a1-access-hold.md` : aucune écriture dans le worktree backend docs.

## Commits et fichiers par tâche

| Tâche | Commit | Message | Fichiers |
|---|---|---|---|
| 1 | fa67240 | feat(off-hours): planner | app/core/off_hours.py ; tests/test_off_hours_planner.py |
| 2 | d368942 | feat(off-hours): window columns, intent table, hold | app/core/access_dates.py ; app/core/db.py ; tests/test_off_hours_db.py |
| 3 | 23bdf3a | feat(off-hours): minute pass and targeted dispatch | app/ui/app.py ; app/core/off_hours_push.py ; app/core/ultra_engine.py ; tests/test_off_hours_app_wiring.py |
| 4 | 4b1acfd | feat(off-hours): removal steps leave the held set out of the ceiling | app/core/off_hours.py ; app/core/push_safety.py ; app/core/ultra_engine.py ; app/core/device_sync.py ; tests/test_off_hours_removal_bound.py |
| 5 | bd66807 | feat(off-hours): QR OFF_HOURS refusal | app/core/access_dates.py ; app/core/access_verification.py ; tauri-ui/src/pages/PopupWindow.tsx ; tests/test_off_hours_qr.py |
| 6 | HEAD (commit de release final) | release: MonClub Access 1.4.38 (off-hours) | update.json ; guide_for_agents_and_dev.md ; tauri-ui/package.json ; tauri-ui/package-lock.json ; tauri-ui/src-tauri/{tauri.conf.json,Cargo.toml,Cargo.lock} ; copie du plan et ce rapport ; corrections de revue dans app/core/{access_verification.py,db.py,off_hours.py,off_hours_push.py,push_safety.py,ultra_engine.py}, tests/test_off_hours_{app_wiring,db,qr}.py ; deux fixtures de tests/test_qr_allowed_days.py |

Les corrections de revue de la tâche 6 ferment les races retrait/réouverture et les escalades vers une passe complète ; elles restent dans le sixième commit, sans modifier les cinq commits précédents.

## Les cinq points de revue

1. **Sauvegarde / patch / logout.** `db.py:1710` conserve les intentions lors de la réconciliation des copies tenues ; `db.py:2083` recalcule les mouvements depuis le roster réellement écrit. `app.py:1717` applique les heures avant toute distribution de la passe de date. Logout supprime l'intention (`db.py:5369`), le patch oublie fenêtre/copie/intention (`db.py:6180`). Le worker revérifie l'état local avant de livrer une commande (`ultra_engine.py:1436`). Tests : `test_full_and_delta_saves_rehold_using_existing_intent`, `test_fast_patch_forgets_hours_and_intent`, `test_hours_move_after_date_step_uses_only_targeted_channel`, plus les régressions `test_protocol2_save_and_flip.py` et `test_p3b1_app_wiring.py`.
2. **Coexistence des tenues.** `db.py:1996` exclut les copies off-hours du restaurateur de date. `db.py:2083` transfère à la raison date lors de la libération si expiré, gelé ou pas commencé. Tests : `test_date_hold_then_hours_hold`, `test_off_hours_release_transfers_to_date_without_another_flip` (trois raisons), `test_hold_release_idempotence_and_fingerprints`.
3. **Borne exacte.** `ultra_engine.py:5253` et `device_sync.py:3637` divisent les vrais candidats en planifiés / imprévus. `push_safety.py:95` vérifie encore les leases pour des retraits uniquement planifiés, et seuls les imprévus peuvent correspondre à une confirmation. Tests : `test_standalone_exact_hold_bound`, `test_pullsdk_exact_hold_bound` (40 % autorisés, 40 imprévus refusés, 30 planifiés + 12 imprévus contre seuil 10 refusés, tout tenu autorisé), `test_planned_holds_still_obey_leases_and_confirm_only_unplanned`.
4. **ACCOUNT.** `off_hours.py:102` et `:118` n'exemptent pas un pin encore désiré par une autre formule éligible ; `off_hours_push.py:5` ne programme pas son retrait. Les handlers existants conservent leur collapse par personne et leurs contrôles de propriété. Tests : `test_account_open_membership_keeps_its_pin_and_errors_do_not_exempt`, `test_revokes_are_owned_and_use_payload_mode_and_device_plan_filter`, plus les 36 tests `test_account_pin_device_sites.py`.
5. **Mode manuel ciblé.** `off_hours_push.py:29` distribue uniquement les identifiants concernés. `ultra_engine.py:1423` remplace une commande off-hours en attente par le nouvel état ; `:1436` réessaie une erreur après 60 s ; `:1689` empêche l'escalade interne vers une passe complète ; `UltraEngine.request_sync_now` interdit le fallback scheduler pour cette origine. Tests : `test_manual_mode_pending_retries_and_reverses_at_window_end`, `test_release_replaces_queued_hold_and_failed_release_is_retried`, `test_failed_hold_cannot_escalate_and_active_release_wins`, `test_off_hours_never_falls_back_to_a_general_scheduler`, `test_release_survives_hold_discovery_failure`, `test_discovery_error_releases_existing_holds_too`.

## Contrat réel et écarts au plan

- Backend lu en lecture seule sur `claude/off-hours-b2` : `AccessWindowDto.offHours`, `ActiveMemberUserV2Dto.offHours`, record `OffHoursWindow(day,startMinute,durationMinutes)`. Payload effectivement implémenté : protocole 2, liste par formule sur users/memberWindows/upcoming, absente si vide ; pas d'intersection ACCOUNT calculée au backend, pas de champ offHoursVersion. L'index et A1 correspondent au code ; la section 5 de la spec initiale est dépassée sur ces deux points.
- L'intention survit à une sauvegarde complète normale. Dans le code réel, la suppression globale des fenêtres de `_save_sync_cache` désigne le logout/reset ; seule cette branche efface globalement l'intention. Cela satisfait le test de sauvegarde complète du plan.
- Le canal général peut convertir une erreur de retrait en synchronisation complète, et un ajout ne remplace pas un retrait encore en attente. Une petite file spécifique au worker, réutilisant les handlers / connexions existants, remplace donc la simple réutilisation des files autoritaires proposée par le plan. Pas de nouveau thread ni connexion.
- `off_hours_in_play` renvoie True en cas d'erreur de lecture pour déclencher une libération fail-open, plutôt que False proposé par le plan. `force_release` permet aussi de libérer les tenues existantes lorsque la découverte des dispositifs/propriétés échoue. L'exception d'une découverte ne perd jamais les libérations déjà commitées.
- Le contrôle de lease reçoit le nombre physique de retraits même lorsque le nombre imprévu vaut zéro. La confirmation et les rapports de dépassement ne comparent que les imprévus.
- Le scénario numérique « 30 tenus + 12 départs contre 70 désirés, donc seuil 10 » est faux : 25 % de 70 vaut 17,5, et le plan demande même d'ajouter les planifiés au dénominateur. Le test de seuil 10 utilise zéro désiré + 30 planifiés, puis 12 imprévus ; le scénario 40 % utilise bien 60 désirés + 40 planifiés.
- Pour les seules formules portant des heures, la raison date précède OFF_HOURS et le refus roster. L'ordre existant des formules sans heures reste inchangé. Un changement de suspicion d'horloge invalide aussi la génération du snapshot QR.
- La version est celle explicitement demandée : 1.4.38. Le script officiel met aussi package-lock.json à jour. La TV reste 1.4.35.
- Le plan annonçait quatre erreurs TypeScript préexistantes ; la commande exécutée ici termine avec zéro erreur.
- Deux fixtures QR inséraient les cinq/sept anciennes colonnes sans les nommer : adaptation aux colonnes explicites, autorisée par Task 6. Aucune assertion métier de régression modifiée.
- Plan source laissé intact hors worktree A1 ; copie locale cochée pour respecter simultanément le pointage et l'isolation. Tests nouveaux écrits par tâche, lancés en fin d'implémentation selon la règle de test léger. Quatre cas supplémentaires issus de revue ont été exécutés individuellement, sans relancer les cas déjà verts.
- Revue indépendante en lecture seule effectuée ; les problèmes concrets signalés ont été corrigés. Aucun P1 restant signalé à sa dernière lecture.

## Validation

**602 tests Python distincts réussis : 68 nouveaux + 534 régressions.**
La première exécution QR avait 104 réussites, 7 échecs et 5 erreurs sur les anciennes fixtures SQL ; les 12 cas concernés réussissent après adaptation.
Un seul processus pytest à la fois, un fichier par commande. Aucun lancement des deux fichiers floconneux ni de la suite entière.

| Fichier | Résultat final distinct |
|---|---:|
| test_off_hours_planner.py | 17 |
| test_off_hours_db.py | 14 (13 + un nouveau cas ciblé) |
| test_off_hours_app_wiring.py | 11 (9 + deux nouveaux cas ciblés) |
| test_off_hours_removal_bound.py | 11 |
| test_off_hours_qr.py | 15 (14 + un nouveau cas ciblé) |
| test_protocol2_save_and_flip.py | 44 |
| test_access_dates.py | 65 |
| test_p3b1_app_wiring.py | 45 |
| test_push_safety_foundation.py | 18 |
| test_removal_ceiling_pullsdk.py | 8 |
| test_revoke_ownership_skip.py | 15 |
| test_authoritative_revocation_pipeline.py | 31 |
| test_account_pin_device_sites.py | 36 |
| test_access_verification.py | 65 |
| test_qr_allowed_days.py | 116 |
| test_totp_roster_check.py | 64 |
| test_card_decision.py | 27 |

Environnement :
```powershell
# Depuis D:/Monclub/monclub_access_python/.worktrees/off-hours-a1
$env:MONCLUB_ACCESS_DATA_ROOT = 'C:\Users\mohaa\AppData\Local\Temp\off-hours-a1-c83c92bc-e081-45a2-b5f5-417121313d87'
# Dossier créé neuf et vide avant le premier pytest.
# Interpréteur : D:\Monclub\monclub_access_python\.venv\Scripts\python.exe
```

Commandes pytest réellement utilisées (la variable d'environnement ci-dessus est appliquée à chaque appel) :
```powershell
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_planner.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_db.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_app_wiring.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_removal_bound.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_qr.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_protocol2_save_and_flip.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_access_dates.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_p3b1_app_wiring.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_push_safety_foundation.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_removal_ceiling_pullsdk.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_revoke_ownership_skip.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_authoritative_revocation_pipeline.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_account_pin_device_sites.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_access_verification.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_qr_allowed_days.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_totp_roster_check.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_card_decision.py -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_app_wiring.py -k test_release_survives_hold_discovery_failure -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_qr.py -k test_listed_but_expired_membership_keeps_date_priority -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_qr_allowed_days.py -k 'test_an_upcoming_only_credential_opens_on_its_first_day or test_but_not_the_day_before or test_a_renewal_adds_the_starting_membership_to_the_existing_credential or test_untrusted_windows_leave_the_stored_credentials_as_they_are or test_a_failed_date_read_keeps_the_stored_credentials or test_ultra_rescue_refuses_an_expired_member or test_ultra_rescue_opens_for_the_member_on_a_day_inside_the_window or test_agent_decision_refuses_an_expired_member' -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_db.py -k test_explicit_fail_open_releases_despite_a_closed_window -q -p no:cacheprovider --ignore=tests/_pydeps
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' -m pytest tests/test_off_hours_app_wiring.py -k test_discovery_error_releases_existing_holds_too -q -p no:cacheprovider --ignore=tests/_pydeps
```

Autres contrôles :
```powershell
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' tools/check_sql_arity.py
# PASS : 91 fichiers, 415 instructions littérales vérifiées ; 108 construites dynamiquement non vérifiables statiquement.
# Exécuté aussi lors de Task 2 : PASS.
git diff --check
# Exit 0.
& 'D:\Monclub\monclub_access_python\.venv\Scripts\python.exe' packaging/sync_tauri_version_files.py --repo-root 'D:\Monclub\monclub_access_python\.worktrees\off-hours-a1' --component access
# Version synchronisée : 1.4.38, sans build.
# Depuis tauri-ui :
cmd /c npx --no-install tsc --noEmit -p .
# Exit 0, aucune erreur.
cmd /c npm test
# 43 passed, 0 failed, 0 skipped.
```

Les dépendances UI existantes sont accessibles via une jonction node_modules dans le nouveau worktree, sans installation ni modification du checkout principal. Les warnings pytest sont des dépréciations existantes de datetime.utcnow().

## Limites et non vérifié

- Matériel réel non testé ; les tests utilisent SQLite temporaire et des SDK simulés. L'application réelle n'a pas été lancée.
- Précision du planificateur jusqu'à 60 s, puis latence de livraison/réessai au dispositif. Mesure du propriétaire (~3 min pour 300 membres) non reproduite ; sommeil/réveil Windows non mesuré.
- Mode DEVICE PullSDK : pas de commande ciblée par minute ; application au prochain sync normal. Présence effective de clubs dans ce mode non vérifiée.
- Redémarrage après libération locale et avant livraison : file de libération en mémoire perdue ; le full sync de démarrage normal répare, le mode manuel attend « Sync data ». Limite du plan, pas résolue ici.
- Bruit opérateur SKIPPED_NOT_OWNED réduit par la sélection des pins possédés, mais non vérifié sur plusieurs dispositifs réels.
- Une base totalement inaccessible ne permet aucune lecture/restauration locale tant qu'elle n'est pas redevenue accessible. Les erreurs de fenêtres/table d'intention testées libèrent les tenues lisibles ; aucun nouveau retrait n'est autorisé sur doute de propriété.
- Horaires inchangés sur un PC éteint : fail-open jusqu'au démarrage, comme prévu.

## Texte de release demandé

Horaires d'accès par formule : les adhérents d'une formule fermée sont retirés des tourniquets à l'heure de début et remis 5 minutes avant la fin, même sans internet.

Un QR Wigo est refusé pendant la fermeture (« Hors horaires de votre formule »).

Aucun changement pour les clubs qui n'utilisent pas cette option.

