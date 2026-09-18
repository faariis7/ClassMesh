---
name: classmesh-design
description: >
  Design, implement, or review ClassMesh Windows UI/UX. Use for Teacher Console, Student Agent,
  enrollment, settings, diagnostics, installer, status surfaces, accessibility, interaction states,
  and visual QA. Adapts strong UI/UX guidance to desktop Windows rather than web-only patterns.
---

# ClassMesh Design

Use this skill for ClassMesh product UI and interaction work.

The goal is a calm, fast classroom-control interface that makes device state, selection, control actions,
and recovery status immediately understandable without looking like a generic AI dashboard.

## Context first

Before designing:

1. Identify the user: teacher/admin/student.
2. Identify the primary task and time pressure.
3. Inspect existing ClassMesh UI patterns and design tokens before inventing new ones.
4. Check technical constraints: WPF/WinUI/Windows shell behavior, DPI, keyboard, accessibility, and performance.
5. Decide the visual direction in one sentence before implementing.

When available, use **UI/UX Pro Max** as the design knowledge layer and **frontend-design-review** as an
independent critique layer. Do not copy web-specific CSS advice literally into Windows UI.

## Product principles

### Teacher Console

- Prioritize the live student grid, selection state, connection/media health, and the next control action.
- Make single-select, multi-select, focused-view, and bulk-action states visually unmistakable.
- Keep destructive/high-impact commands visually separate from routine classroom controls.
- Do not cover live content with persistent decoration that reduces monitoring usefulness.
- Prefer progressive disclosure for advanced network, codec, and diagnostic detail.

### Student Agent

- Keep the normal surface quiet and minimal.
- Make enrollment, approval, privacy/control state, connection status, and errors explicit.
- Never imply a device is controlled, connected, or secure when the underlying state is uncertain.

### Diagnostics and recovery

- Show actionable state, not vague labels such as "Something went wrong."
- Distinguish control connection, media stream, capture, encode, decode/render, and enrollment failures.
- Give recovery actions only when they are safe and meaningful.

## Windows quality gates

Every production UI change should consider:

- keyboard-only navigation and logical tab order;
- visible focus;
- Narrator/UI Automation semantics;
- Windows high-contrast behavior;
- light/dark theme if supported by the product surface;
- 100%, 125%, 150%, and 200% DPI scaling;
- resizing and minimum-window behavior;
- long device names and localization-safe layout;
- loading, empty, offline, degraded, permission-denied, and error states;
- reduced or restrained motion;
- no information conveyed by color alone;
- touch targets where touch use is plausible;
- rendering/performance impact on the Teacher live-grid path.

## Design-system rules

- Use named semantic tokens rather than one-off colors, spacing, radii, or typography values.
- Define component states before styling: default, hover, pressed, selected, disabled, focus, warning, error.
- Reuse an existing component before creating a new pattern.
- If a new pattern is required, document why the old one fails.
- Prefer strong hierarchy and controlled density over decorative card grids.
- Avoid generic gradients, excessive glassmorphism, oversized rounded cards, and decorative motion without product value.

## Review workflow

1. State the user task and visual direction.
2. Verify information hierarchy and primary action.
3. Check all states, not only the happy path.
4. Check Windows accessibility and DPI/resizing behavior.
5. Compare against design tokens and existing patterns.
6. Inspect runtime screenshots at representative sizes.
7. When available, use Windows UI Automation/runtime inspection rather than reviewing XAML/code alone.
8. Classify findings as blocking, major, or refinement.
9. Re-run the visual/runtime check after fixes.

## Acceptance checklist

- [ ] Primary task/action is obvious.
- [ ] Grid/focus/multi-select states are unambiguous.
- [ ] Offline/degraded/recovery states are distinct.
- [ ] Keyboard and visible focus work.
- [ ] UI Automation/Narrator naming is sensible.
- [ ] 125% and 200% DPI do not clip core controls.
- [ ] Long text/localization does not break the layout.
- [ ] No hardcoded visual values bypass the design system without rationale.
- [ ] Runtime screenshot/inspection matches the intended design.
- [ ] UI work does not add avoidable latency or CPU/GPU pressure to the media path.
