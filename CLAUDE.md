# Claude Code instructions

Project guidance for Claude Code sessions in this repository. The README
covers architecture, configuration, and the security model. This file covers
how finished work is reported back.

## Task completion report

Every task ends with a completion report as the final message. Its purpose is
to let the reader tell, at a glance and without scrolling back, whether the
whole request was finished, and if not, exactly what is still open, why it was
left open, and what to do about it. This matters most for long or multi-step
tasks, but the status line is required on every task.

### Status line

The first line of the final message is exactly one of:

- `Status: COMPLETE` - every part of the request is done and verified. Nothing
  is left for the user to do.
- `Status: PARTIAL` - some of the request is done. Every unfinished part is
  listed below with its own reason and next step.
- `Status: BLOCKED` - no meaningful part could be delivered. The report says
  what input is needed before work can continue.

Rules for choosing the status:

- COMPLETE is allowed only when every requested item is done and every check
  that was run passed. A skipped, failed, or unverifiable check makes the task
  PARTIAL, with that check listed as remaining.
- A request with several parts is COMPLETE only when all of them are done.
  Finishing the easy parts is PARTIAL.
- If the task called for a commit or push, the work is not done until it is
  pushed. Uncommitted work in a remote session does not survive the session.
- Never soften a PARTIAL into a COMPLETE with wording such as "mostly done",
  "should work", or "the remaining bit is trivial".

### Report body

After the status line, in this order:

1. **Done** - what was delivered, briefly. For a multi-part request, restate
   each part of the original request with `Done` or `Not done` next to it so
   nothing can be silently dropped. When work was pushed, name the branch and
   the commit.
2. **Verified** - what was actually run to confirm the work (tests, linters,
   audits, a manual check) and the result. If a check was not run, say so
   explicitly instead of leaving it out. Never present an inference as a
   verified result.
3. **Remaining** - required whenever the status is not COMPLETE. One entry per
   unfinished item, each with:
   - what is still open, tied to the part of the request it belongs to;
   - why it was left open. Acceptable reasons are specific: a decision only
     the user can make (name the decision), access or credentials or data the
     session does not have, an action that is destructive or irreversible and
     needs confirmation, a failing check that could not be fixed (include the
     failure output), or a scope judgment (say why it is out of scope). "Ran
     out of time" or "left for follow-up" without a concrete reason is not
     acceptable;
   - the recommended path forward: one concrete next step, given as a
     recommendation rather than a menu. Say who does it, the user or Claude on
     the next turn, and what the user must provide, if anything.

### Placement

- The report is the final chat message of the task. When the task ends in a
  pull request, the same report goes in the pull request description.
- Keep it short. The status line and the Remaining section are the parts a
  reader on a phone must be able to take in within a few seconds.
