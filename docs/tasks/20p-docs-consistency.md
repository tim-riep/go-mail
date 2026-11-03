# Auftrag 20p: Funde der Konsistenzprüfung der Dokumente (nur Dokumentation)

Es gelten die festen Vorgaben aus `docs/tasks/00-vorgaben.md` wörtlich.
- Basis: Arbeitsbranch `claude/quirky-keller-hjsl5i` bei 9568de5 oder später, eigener Worktree.
- Darf ändern: `docs/DECISIONS.md`, `docs/AUDIT.md`, `docs/HANDOFF.md`, `docs/RUNBOOK.md` (nicht Abschnitt 7.3, den ändert parallel 21d), `docs/QUESTIONS.md`. Nicht `docs/ORCHESTRATION.md` (führt der Orchestrator).
- Quelle: `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/consistency-review.md` (H1, M1–M5, L1–L12) und `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/final/review-clientdir/notes.md` (L1, L6: AUDIT-Zeile „FIFO an Stellen von R41“, RUNBOOK 3.2 „Markierung“).

## Umfang

1. **H1:** Überall, wo ein Worktree-Commit als Stand genannt ist, den Commit im Arbeitsbranch nennen (Zuordnung: b14d798 → 858b2f1; 869a196 → 211a45b; 1a57314 → b674ae3 (ohne die 20m-Tests); cb2344c → b155e1f; bc0d0f9/b2032d5 → d85da00; 7ffed5c → 3e06f23; 302c6db und 1d49e6d sind Merges im Worktree: „Volllauf auf dem Code von 858b2f1“ bzw. „… von b674ae3 ohne 20m-Tests“). Prüfe jede Zuordnung selbst mit `git diff --stat <a> <b> -- internal cmd scripts`. Wo ein Volllauf auf einem Worktree-Commit lief, das so sagen und den gleichwertigen Branch-Commit nennen.
2. **M1–M5** und **L1–L12** wie in der Quelle vorgeschlagen, jeweils am Code oder an `git log` geprüft. Für M2: D85-Nachtrag 20m (was gebaut ist: Stillstand nur bei Run-Queue > 500 ms und eigener CPU ≤ 500 ms, Zustand T nur bei Stopp des Tests, Lücken > 500 ms; einmal wiederholen, dann Skip mit Messwerten; Restgrenzen aus `docs/tasks/20-notes.md` „Aus der Prüfung von 20m“) und die Regel „jeder Skip dieser Tests wird im Abnahmelauf geprüft“ in AUDIT 6.1 und HANDOFF. Für M3: Q19/Q8 sind mit D93 entschieden, Umsetzung in Auftrag 21 läuft; RUNBOOK 7.3 nicht ändern (21d), nur Verweise anderswo.
3. Die beiden Punkte aus der Gesamtprüfung (AUDIT-Zeile zur FIFO am Schlüsselspeicher; RUNBOOK 3.2 „vor dem Anlegen seiner Markierung“).

## Fertig

- Jede Änderung belegt. Ein Commit mit `Task: docs/tasks/20p-docs-consistency.md`, ohne Co-Authored-By. Nicht pushen. Notizen in `/tmp/claude-0/-home-user-go-mail/531d5185-783f-5990-a7a5-eb0759016cf4/scratchpad/impl20p/notes.md`. Keine Testläufe.
