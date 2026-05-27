# Screenshots

Drop **redacted** images here and reference them from the top-level README.
These show live data (hostnames, IPs, agent names); the text sanitisation gate
does not scan image pixels, so crop/blur by hand before committing.

Worth capturing:

1. `wazuh-dashboard.png` - the overview: agents reporting, alert level
   distribution over time. Redact agent names / IPs.
2. `alert-levels.png` - the alert-level histogram showing the long tail sitting
   below the notification threshold (the tuning working).
3. `telegram-alert.png` - a real-time level-7+ push: agent, rule, one-liner.
4. `rule-tiers.png` - the local_rules.xml open, showing the three-tier structure.
