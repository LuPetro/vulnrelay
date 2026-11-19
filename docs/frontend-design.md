# Frontend design system

The operator approved the Overview direction and requested the same treatment across the application on 2026-11-19. The local UI now shares its operating-journal identity across navigation, assets, catalog, rules, connectors, vulnerability history/details and settings. The existing logo, Overview animation and notification behavior remain recognizable.

## Shared foundations

The application serves IBM Plex Sans and IBM Plex Mono from its own `/fonts/plex` assets; it makes no font-CDN requests. Sans supplies reading text and controls. Mono is reserved for identifiers, timestamps, counts, section labels and technical evidence. Shared body defaults to 16px, form labels to 14px, and useful supporting metadata to at least 12px. The separately composed Overview keeps its reviewed proportions.

Light mode uses warm paper (`#f6f7f3`), white working surfaces, dark ink (`#1c2d32`) and restrained green (`#22634e`). Dark mode uses the same semantic roles with charcoal paper and pale green. Error and waiting states retain dedicated red and amber colors, explanatory text and status labels. Do not communicate a state through color alone.

The spacing scale is 4/8/12/16/24/32/40/48px. Shared CSS variables live in `frontend/src/style.css`; the Overview illustration retains scoped `--ov-*` variables in `overview.css`. Most working surfaces use three-pixel corners and one-pixel rules. There are no decorative gradients, glows or drop shadows. Primary actions use green; secondary actions stay quiet until hover or focus.

## Layout follows the task

- The sidebar is a ruled navigation register with one clear selected location. On phones it becomes a horizontal navigation strip, with an accessible theme control beside the masthead.
- Inventory, rules and destinations are numbered rows. Names, identity/context, enabled state and actions follow a consistent reading order without repeating decorative icons.
- Editors have an explanation, labelled fields and a distinct action row. The nested rule builder retains explicit AND/OR/NOT controls and uses a vertical composition on narrow screens.
- Catalog technologies remain individual selectable items because their selected state is meaningful. Packs use quieter grouped lists. Matching evidence, import review and environment context stay available alongside selection.
- Vulnerability records put the CVE identifier and description first. Severity and numeric metrics remain distinct, including on a phone. Details keep source assessments and matching evidence available separately.
- Settings use two functional sections for access and monitoring, stacking at smaller widths. Empty states describe a concrete next step rather than suggesting that sample data is live.

All existing operations remain available. Queue and delivery-window controls use the same semantic palette and forms. Motion remains concentrated in the illustrative Overview and real counter changes; navigation, forms and lists do not add gratuitous entrance animations.

## Review and verification

Use the normal [backed-up Docker update](catalog.md#update-and-test-an-existing-docker-installation). Check light and dark themes, keyboard focus, manual asset entry, catalog selection/review/import, nested rules, connector setup and delivery windows, queue/history, CVE details and settings. Check phone widths down to 320px without horizontal page overflow. System reduced-motion remains honored.

The shared VPS must not run a local browser or container build; browser interactions, automated accessibility checks and screenshot artifacts are verified in GitHub CI. Screenshots and automated checks support visual review but do not establish comprehensive accessibility or production readiness. Do not change an operator-owned running installation as part of design verification.
