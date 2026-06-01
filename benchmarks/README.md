# Benchmark

This benchmark consists of 10 known concurrency bugs in the Linux kernel, covering subsystems including networking (TUN, AF_NETROM, Bluetooth, ILA), filesystems (btrfs, F2FS), and VFS. Bugs were sourced from syzbot reports and kernel commit history, filtered to retain only those with both a confirmed patch and a reproducible proof-of-concept.

| ID | Bug | Fix Commit | repro |
|----|-----|------------|-------|
| 1 | 3b9bc84d | [3b9bc84d](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3b9bc84d311104906d2b4995a9a02d7b7ddab2db) | syz-prog |
| 2 | 61179292 | [61179292](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=611792920925fb088ddccbe2783c7f92fdfb6b64) | syz-prog |
| 3 | 88b1afbf | [88b1afbf](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=88b1afbf0f6b221f6c5bb66cc80cd3b38d696687) | syz-prog |
| 4 | cb2239c1 | [cb2239c1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=cb2239c198ad9fbd5aced22cf93e45562da781eb) | syz-prog |
| 5 | CVE-2023-31083 | [9c33663a](https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9c33663af9ad115f90c076a1828129a3fbadea98) | c, syz-prog |
| 6 | CVE-2024-42111 | [724d8042](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=724d8042cef84496ddb4492dc120291f997ae26b) | syz-prog |
| 7 | CVE-2024-44941 | [d7409b05](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d7409b05a64f212735f0d33f5f1602051a886eab) | syz-prog |
| 8 | CVE-2024-49903 | [d6c1b359](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d6c1b3599b2feb5c7291f5ac3a36e5fa7cedb234) | syz-prog |
| 9 | CVE-2024-50125 | [1bf4470a](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1bf4470a3939c678fb822073e9ea77a0560bc6bb) | syz-prog |
| 10 | CVE-2024-57900 | [260466b5](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=260466b576bca0081a7d4acecc8e93687aa22d0e) | syz-prog |
