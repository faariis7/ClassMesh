---
name: frontend-design-review
description: >
  Review and create distinctive, production-grade frontend interfaces with high design quality and design system compliance.
  Evaluates using three pillars: frictionless insight-to-action, quality craft, and trustworthy building.
  USE FOR: PR reviews, design reviews, accessibility audits, design system compliance checks, creative frontend design,
  UI code review, component reviews, responsive design checks, theme testing, and creating memorable UI.
  DO NOT USE FOR: Backend API reviews, database schema reviews, infrastructure or DevOps work, pure business logic
  without UI, or non-frontend code.
acknowledgments: |
  Design review principles and quality pillar framework created by @Quirinevwm (https://github.com/Quirinevwm).
  Creative frontend guidance inspired by Anthropic's frontend-design skill
  (https://github.com/anthropics/skills/tree/main/skills/frontend-design). Licensed under respective terms.
---

# Frontend Design Review

Review UI implementations against design quality standards and your design system **OR** create distinctive, production-grade frontend interfaces from scratch.

## Two Modes

### Mode 1: Design Review
Evaluate existing UI for design system compliance, three quality pillars (Frictionless, Quality Craft, Trustworthy), accessibility, and code quality.

### Mode 2: Creative Frontend Design
Create distinctive interfaces that avoid generic "AI slop" aesthetics, have clear conceptual direction, and execute with precision.

## Creative Frontend Design

Before coding, commit to an aesthetic direction:
- **Purpose**: What problem does this solve? Who uses it?
- **Tone**: minimal, maximalist, retro-futuristic, organic, luxury, playful, editorial, brutalist, art deco, soft/pastel, industrial, etc.
- **Constraints**: Framework, performance, accessibility requirements.
- **Differentiation**: What makes this distinctive and context-appropriate?

### Aesthetics Guidelines

- **Typography**: Distinctive fonts that elevate aesthetics. Pair a display font with a refined body font. Avoid Inter, Roboto, Arial, Space Grotesk.
- **Color & Theme**: Cohesive palette with design tokens. Dominant colors + sharp accents > timid, evenly-distributed palettes.
- **Motion**: Prefer intentional, coherent motion over scattered micro-interactions.
- **Spatial Composition**: Use deliberate composition and controlled density.
- **Backgrounds**: Use atmosphere only when it supports the product.

**AVOID**: Overused fonts, cliched color schemes, predictable layouts, cookie-cutter design without context-specific character.

## Design Review

### Design System Workflow

**Before implementing:**
1. Review the component library/design system for API and usage.
2. Use exact design specs when available.
3. Implement using design-system components + design tokens.

**During review:**
1. Compare implementation to the approved design.
2. Verify design tokens are used instead of hardcoded values.
3. Check all variants/states.
4. Flag deviations that need design approval.

### Review Process

1. Identify user task.
2. Check the design system for matching patterns.
3. Evaluate aesthetic direction.
4. Identify scope.
5. Evaluate each pillar.
6. Prioritize issues as blocking/major/minor.
7. Provide concrete recommendations.

### Core Principles

- **Task completion**: Minimize unnecessary interactions.
- **Action hierarchy**: Keep primary actions clear.
- **Onboarding**: Prefer smart defaults and contextual guidance.
- **Navigation**: Clear entry/exit paths and recovery.

## Quality Pillars

### 1. Frictionless Insight to Action

Evaluate whether the primary task is efficient and the next action is obvious.

### 2. Quality is Craft

Evaluate design-system compliance, visual coherence, responsive/adaptive behavior, and accessibility.

### 3. Trustworthy Building

Evaluate transparent system state, actionable errors, and trustworthy behavior.

## References

- [Review output format](references/review-output-format.md)
- [Review type modifiers](references/review-type-modifiers.md)
- [Quick checklist](references/quick-checklist.md)
- [Pattern examples](references/pattern-examples.md)

## Upstream

Vendored and lightly adapted for cross-platform wording from:
https://github.com/microsoft/skills/tree/main/.github/skills/frontend-design-review

Microsoft Skills repository is MIT licensed. Re-check upstream before materially updating this vendored copy.
