# BrownOS — Filesystem Structure & Content

## Complete Directory Tree

All IDs are the numeric identifiers used by the VM's filesystem syscalls (readdir, name, readfile).

```
/ (id 0, directory)
├── bin/ (id 1, directory)
│   ├── false (id 16, file, 0 bytes)
│   ├── sh (id 14, file, 0 bytes)
│   └── sudo (id 15, file, 0 bytes)
├── etc/ (id 2, directory)
│   ├── brownos/ (id 3, empty directory)
│   └── passwd (id 11, file, 181 bytes)
├── home/ (id 22, directory)
│   ├── dloser/ (id 50, empty directory)
│   └── gizmore/ (id 39, directory)
│       └── .history (id 65, file, 49 bytes)
├── sbin/ (id 9, empty directory)
└── var/ (id 4, directory)
    ├── log/ (id 5, directory)
    │   └── brownos/ (id 6, directory)
    │       └── access.log (id 46, file, dynamic content)
    └── spool/ (id 25, directory)
        └── mail/ (id 43, directory)
            └── dloser (id 88, file, 177 bytes)
```

### Hidden/Unlinked Entry

```
[hidden] wtf (id 256, file)
```

- Not reachable from any `readdir` output
- Only discoverable by directly querying `name(256)` and `readfile(256)`
- IDs 257–1024 were scanned — no additional entries found
- IDs beyond 1024 were NOT scanned (additive encoding supports arbitrary large numbers)

---

## File Contents

### /etc/passwd (id 11) — 181 bytes

```
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

**Analysis**:
- **root**: UID 0, password field `x` (locked), shell `/bin/false` (no login)
- **mailer**: UID 100, password field `x` (locked), home `/var`, shell `/bin/false`
- **gizmore**: UID 1000, password field `GZKc.2/VQffio` (classic `crypt(3)` DES hash), home `/home/gizmore`, shell `/bin/sh`
- **dloser**: UID 1002, password field `x` (locked/shadow), home `/home/dloser`, shell `/bin/false`

**The hash `GZKc.2/VQffio`**:
- Salt: `GZ` (first 2 characters)
- Algorithm: Traditional DES crypt(3)
- Cracked password: **`ilikephp`** (confirmed via `crypt("ilikephp", "GZ") == "GZKc.2/VQffio"`)

### /home/gizmore/.history (id 65) — 49 bytes

```
sodu deluser dloser
ilikephp
sudo deluser dloser
```

**Interpretation**:
- Line 1: `sodu deluser dloser` — typo of "sudo" (failed command)
- Line 2: `ilikephp` — accidental password leak (typed as a command instead of a password prompt)
- Line 3: `sudo deluser dloser` — successful command to delete the `dloser` user

The password `ilikephp` cracks gizmore's hash in `/etc/passwd`. However:
- There is no interactive shell syscall in BrownOS
- `/bin/sh` is a 0-byte file
- Submitting `ilikephp` to WeChall was **rejected**

### /var/spool/mail/dloser (id 88) — 177 bytes

```
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```

**This is the critical hint that reveals**:
- Syscall 201 (0xC9) exists as a "backdoor"
- The argument must be `00 FE FE` (which is `nil` in bytecode)
- The narrative: dloser installed a backdoor and emailed "boss@evil.com" about it, but the mailer daemon sent a delivery failure notice to dloser's local mailbox

### /var/log/brownos/access.log (id 46) — dynamic

```
<unix_timestamp> <client_ip>:<client_port>
```

Example: `1706832000 192.168.1.100:54321`

- Content changes **every connection** (shows current connection info)
- Reading it twice in the **same program** yields the same line (no mid-connection mutation)
- Calling syscall 8 between two reads does NOT change the second read (no side-effect)

### /bin/false (id 16) — 0 bytes

Empty file. On real Unix, `/bin/false` is used as a login shell to disable interactive logins. Here it's 0 bytes but the `/etc/passwd` entries still communicate the same narrative.

### /bin/sh (id 14) — 0 bytes

Empty file. There is no interactive shell capability in BrownOS.

### /bin/sudo (id 15) — 0 bytes

Empty file. No privilege escalation mechanism exists.

### Hidden: wtf (id 256)

- **Name**: `wtf`
- **Content**: `Uhm... yeah... no...\n`
- **readdir(256)**: `Right(4)` "Not a directory" (it's a file)
- **Not reachable from directory tree** — no `readdir` output references it
- Discovered by testing `name(256)` with the additive encoding (`256 = 128 + 128`)
- Appears to be a troll/easter egg

---

## Filesystem ID Summary Table

| ID | Type | Name | Parent | Size | Notes |
|:---:|:---:|---|:---:|:---:|---|
| 0 | dir | / | — | — | Root directory |
| 1 | dir | bin | 0 | — | |
| 2 | dir | etc | 0 | — | |
| 3 | dir | brownos | 2 | — | Empty |
| 4 | dir | var | 0 | — | |
| 5 | dir | log | 4 | — | |
| 6 | dir | brownos | 5 | — | |
| 9 | dir | sbin | 0 | — | Empty |
| 11 | file | passwd | 2 | 181 | Password file |
| 14 | file | sh | 1 | 0 | Empty |
| 15 | file | sudo | 1 | 0 | Empty |
| 16 | file | false | 1 | 0 | Empty |
| 22 | dir | home | 0 | — | |
| 25 | dir | spool | 4 | — | |
| 39 | dir | gizmore | 22 | — | |
| 43 | dir | mail | 25 | — | |
| 46 | file | access.log | 6 | dynamic | Connection log |
| 50 | dir | dloser | 22 | — | Empty |
| 65 | file | .history | 39 | 49 | Password leak |
| 88 | file | dloser | 43 | 177 | Backdoor hint |
| 256 | file | wtf | (hidden) | ~21 | Easter egg |

---

## Narrative Interpretation

The filesystem tells a story:
1. **gizmore** is the system administrator with password `ilikephp`
2. **dloser** is a malicious user who installed a backdoor (syscall 201)
3. dloser emailed "boss@evil.com" about the backdoor but the email bounced
4. gizmore discovered something and tried to `deluser dloser` (seen in `.history`)
5. The dloser account still exists in `/etc/passwd` but with no login shell
6. The hidden file "wtf" (id 256) appears to be gizmore's reaction

This narrative is consistent with the challenge framing: you're investigating a compromised system and need to exploit the backdoor to solve it.
