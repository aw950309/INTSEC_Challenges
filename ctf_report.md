# CTF Flag Hunting Report - Phase 3 IntSec 2025

**Date:** 2025-12-19 04:01:55
**Total Flags Found:** 17
**Images Scanned:** 17

**Compliance:** Network-only attacks (no container command execution)

## Summary by Image

### elnino/intsec-2025:hardened-v2
- **Flags Found:** 1
  - Flag #5: `7bdf2cc0c21a12b4d39b30bcdb6729b53c284247` (SQL Injection)

### cait7999/passoire-hardened:latest
- **Flags Found:** 1
  - Flag #5: `7a4385844851763ddd795f4771e2d5a665de62ff` (SQL Injection)

### aw950309/passoire:v1
- **Flags Found:** 1
  - Flag #5: `24b3a52ee00e5da545a95071c1a21419f9afa417` (SQL Injection)

### tomej2/group50repository:latest
- **Flags Found:** 1
  - Flag #5: `609c88dbccf0bd62db98415fa367bee1c584fc41` (SQL Injection)

### intsecgroup3/group3-app-image:v2.0
- **Flags Found:** 1
  - Flag #5: `0180362c6b857684c0d01877e73940ca3815e13b` (SQL Injection)

### tylerponte/intsec:intsec-group8
- **Flags Found:** 1
  - Flag #5: `eca74a6f8d0c49d3234fd2b539a259e36462790c` (SQL Injection)

### chabsieger/passoire-secure:v1
- **Flags Found:** 1
  - Flag #5: `cb573f0cb482b9e46d67ca0061791bc088edbdb7` (SQL Injection)

### aimo2926/passoire-hardened:v1
- **Flags Found:** 1
  - Flag #5: `84c6bf14e56aa4334d08ed4fb2bbf6ff5a63f526` (SQL Injection)

### uthpalavi/passoire20-secure:v1
- **Flags Found:** 1
  - Flag #5: `5679aeb036d35d83abe26df4c96ab14f861b1a38` (SQL Injection)

### gabbipls/new-passoire-intsec25:phase2
- **Flags Found:** 1
  - Flag #5: `359bef67e8c9ba435529cf92f78d0241e56e4816` (SQL Injection)

### codyprince/test:latest
- **Flags Found:** 1
  - Flag #5: `ff807ef5881b35995b51563dc03694d6fe22794c` (SQL Injection)

### martijnme/intro-sec-group-37:v1.1.7
- **Flags Found:** 1
  - Flag #5: `8e12fb7a05b9b84ae19a7cd111ee851e43d1b846` (SQL Injection)

### kali6753/passoire:NEW
- **Flags Found:** 1
  - Flag #5: `9cf049423a6ff90a71c723917e8a4539bf79e7cb` (SQL Injection)

### fabiopereira98/project_group52:final
- **Flags Found:** 1
  - Flag #5: `a3e1d8a2aa566df2ff248e732b558b51d88c31d9` (SQL Injection)

### askanberg/grupp57:v3
- **Flags Found:** 1
  - Flag #5: `04a01d63fa8ea277a8e0782d003af7ff2134b389` (SQL Injection)

### g62intsec/g62intsec-public:latest
- **Flags Found:** 1
  - Flag #5: `07415ffc1ee2aa63974601f9575c0de1cf611af8` (SQL Injection)

### alexkord/saferpoint:latest
- **Flags Found:** 1
  - Flag #5: `77bed512550d70ac2e89b4e041eed0160ffaa2d9` (SQL Injection)

## Detailed Flag List

| # | Image | Flag # | Flag Value | Discovery Method | Comment |
|---|-------|--------|------------|------------------|---------|
| 1 | intsec-2025 | 5 | `7bdf2cc0c21a12b4d39b30bcdb6...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 2 | passoire-hardened | 5 | `7a4385844851763ddd795f4771e...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 3 | passoire | 5 | `24b3a52ee00e5da545a95071c1a...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 4 | group50repository | 5 | `609c88dbccf0bd62db98415fa36...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 5 | group3-app-image | 5 | `0180362c6b857684c0d01877e73...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 6 | intsec | 5 | `eca74a6f8d0c49d3234fd2b539a...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 7 | passoire-secure | 5 | `cb573f0cb482b9e46d67ca00617...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 8 | passoire-hardened | 5 | `84c6bf14e56aa4334d08ed4fb2b...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 9 | passoire20-secure | 5 | `5679aeb036d35d83abe26df4c96...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 10 | new-passoire-intsec25 | 5 | `359bef67e8c9ba435529cf92f78...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 11 | test | 5 | `ff807ef5881b35995b51563dc03...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 12 | intro-sec-group-37 | 5 | `8e12fb7a05b9b84ae19a7cd111e...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 13 | passoire | 5 | `9cf049423a6ff90a71c723917e8...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 14 | project_group52 | 5 | `a3e1d8a2aa566df2ff248e732b5...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 15 | grupp57 | 5 | `04a01d63fa8ea277a8e0782d003...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 16 | g62intsec-public | 5 | `07415ffc1ee2aa63974601f9575...` | SQL Injection | Found via SQLi at /passoire/index.php |
| 17 | saferpoint | 5 | `77bed512550d70ac2e89b4e041e...` | SQL Injection | Found via SQLi at /passoire/index.php |
