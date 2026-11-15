# VulnRelay visual identity

The original VulnRelay mark combines a split V with a separate relay point. Cobalt represents incoming intelligence; mint marks the onward signal. The mark is a native SVG: transparent, scalable, and usable without external fonts or image services.

Assets in `frontend/public/brand/`:

- `vulnrelay-mark.svg`: transparent symbol, 64 × 64 viewBox.
- `vulnrelay-wordmark-dark.svg`: dark lettering for light backgrounds.
- `vulnrelay-wordmark-light.svg`: light lettering for dark backgrounds.
- `vulnrelay-brand-sheet.svg`: self-contained preview of the identity.
- `frontend/public/favicon.svg`: compact mark on a navy rounded tile.

Wordmarks use system sans-serif text and may vary slightly with installed fonts. Use the symbol when exact outline consistency is required. Keep clear space around the mark and avoid distorting its proportions. These original assets are distributed with the repository under Apache-2.0.

## Overview behavior

The current [Overview-only design study](overview-design.md) documents typography, the ruled grid, richer processing motion and rollback boundaries. The logo itself is unchanged. IBM Plex font files have their own SIL Open Font License and are served locally with notices.

The animated SVG explains the source → matching/filtering → delivery flow; it is explicitly illustrative, not live traffic or a risk measurement. All counts, source errors, delivery states and heartbeat labels come from the API. Enabled asset counts exclude disabled inventory; sent-message counts include connector tests. A recent worker heartbeat does not guarantee source freshness or destination health. The Overview reports those separately.

Motion uses small CSS animations without a canvas, animation library or external services. Status now refreshes separately every five seconds on visible Overview/Connectors pages. The pause control persists locally in the browser. System reduced-motion preference disables animation, as does a hidden browser tab. Counts come from stored delivery state. The sent counter rolls between actual values on increases and uses k notation above 1,000, with the precise value available to assistive technology and on hover. Mobile and dark layouts use the same operational data.

Update through the normal [Docker update procedure](catalog.md#update-and-test-an-existing-docker-installation). The queue-controls increment includes a database migration; see its [upgrade notes](delivery-queue.md). Credential changes are not required. Hard-refresh the page if an old favicon remains cached.
