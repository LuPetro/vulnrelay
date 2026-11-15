# Overview design study

This is an Overview-only direction for operator review. The navigation, catalog, asset/rule/connector editors, CVE pages, settings, logo, backend and database keep their existing behavior and design. It does not adopt a new design across the whole product. The previous application baseline is development commit `aada585f29b74609d5c06c485a99771526323891`.

## Direction

The page acts as an operating journal: one view of the intelligence route, monitored scope, provider state, deliveries and inventory groups. It replaces promotional hero styling and repeated cards with a ruled page, a numbered section hierarchy, shared baselines and restrained proportions. Warm paper, dark ink and one green status/accent palette make errors and operating states distinct. The existing brand mark is retained unchanged.

IBM Plex Sans supplies the headings and reading text. Its regular, medium and semibold weights distinguish data from supporting information. IBM Plex Mono is reserved for timestamps, metadata and section numbering. Four unmodified WOFF2 files (about 247 KiB total) are served locally and used only inside the Overview; no font CDN is requested in the browser. Original source and full SIL Open Font License notices accompany the assets. The Overview heading and Refresh button are scoped through its main element; other pages do not inherit this typography or palette.

Spacing uses a four-pixel base with 8/12/16/24/32/40/48-pixel steps. Section borders establish the grid. Metrics form one ruled band; environment groups are inventory rows. The source and delivery registers share an asymmetric grid and stack at narrower widths. Small screens get a separately composed vertical signal diagram rather than shrinking desktop labels into unreadable text.

## Motion

The diagram has a shared 6.8-second cycle: source ingress, travelling packets, matching, filter bars and a notification sheet. Line progress and small state changes describe each processing stage. A restrained ring marks a recent worker heartbeat; it does not certify source freshness or successful delivery. Metrics enter with a small positional movement, without changing their real values or fading text through inaccessible contrast.

The illustration is explicitly labelled and does not depict live events. There are no invented traffic rates, risk scores or counter animations. No animation library or canvas is used. Status now has a separate five-second visible-page refresh; its versioned responses preserve counter accuracy. Counter transitions show only real increases. See [delivery queue controls](delivery-queue.md). The pause setting remains in `vulnrelay-motion` local storage. System reduced-motion preference and a hidden browser tab stop animations; hidden desktop/mobile SVG variants do not animate. Motion control stops the whole Overview, including heartbeat and hover transitions.

## Review and rollback

Use the [normal backed-up Docker update](catalog.md#update-and-test-an-existing-docker-installation). The initial design increment changed no schema. The subsequent queue-controls increment includes migration 0007; follow its [upgrade notes](delivery-queue.md#sent-counter-and-updating) before updating. Review the Overview in both themes, at desktop and phone widths, then pause/resume motion and try keyboard navigation. Confirm the other pages keep their previous styles. Error and empty states remain actionable.

The initial work is isolated in the Overview design commits. Since queue controls now build on that layout, restore the earlier visual styles selectively when reviewing a design rollback; do not blindly revert the newer backend or database migration. Do not reset the database or remove a persistent volume to change the design. Broader adoption should wait for operator feedback.
