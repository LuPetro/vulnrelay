# VulnRelay

Self-hosted, asset-aware vulnerability notifications. Alpha software; no production release yet.

Install with Python 3.12+: `pip install .`, then `vulnrelay init`. Configure assets, Telegram destinations and rules using the CLI or the optional local web interface. Run `vulnrelay monitor` to synchronize NVD, CISA KEV and FIRST EPSS and deliver matching notifications. No AI or cloud account is required.

See the repository README for Docker, full configuration, limitations, security and contribution guidance: https://github.com/LuPetro/vulnrelay

Apache-2.0. The source distribution includes the license and database migrations.
