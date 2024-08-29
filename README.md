# Iptables-Best-Rules
Mini Project: Optimal IPTables Configuration for Attack Mitigation
This project aims to design and implement the best IPTables configurations to defend against various cyber attacks. It includes analyzing threats, creating tailored rules for prevention, and ensuring system security while balancing performance and reducing false positives.

**Dependencies**:
Iptables: Version 1.8.7 or higher
xtables-addons-common: Version 3.19-1ubuntu1 or higher

**xtables Modules**:
xt_psd: Used for detecting port scans (Port Scan Detection).
xt_recent: Used for monitoring and managing recent connections or attack attempts (tracking of recent connections).
xt_string: Used for identifying and filtering packets based on specific strings (e.g., DNS queries with particular strings).
