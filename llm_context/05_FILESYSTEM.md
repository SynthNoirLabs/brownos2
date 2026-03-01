# BrownOS — Filesystem Structure & Content

## Complete Directory Tree

```
/ (id 0)
├── bin (id 1)
│   ├── false (id 16)         [0 bytes]
│   ├── sh (id 14)            [0 bytes]
│   └── sudo (id 15)          [0 bytes]
├── etc (id 2)
│   ├── brownos (id 3)        [empty dir]
│   └── passwd (id 11)        [181 bytes]
├── home (id 22)
│   ├── dloser (id 50)        [empty dir]
│   └── gizmore (id 39)
│       └── .history (id 65)  [49 bytes]
├── sbin (id 9)               [empty dir]
└── var (id 4)
    ├── log (id 5)
    │   └── brownos (id 6)
    │       └── access.log (id 46)     [changes per connection]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88)         [177 bytes]
```

## File Contents

### /etc/passwd (id 11)
```
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

- `gizmore` has a classic `crypt(3)` hash: `GZKc.2/VQffio`
- `dloser` has `x` (password in shadow, but /etc/shadow doesn't exist)

### .history (id 65)
```
sodu deluser dloser
ilikephp
sudo deluser dloser
```

- `sodu` = typo, `ilikephp` = password leaked as command
- `sudo deluser dloser` = tried to remove dloser

### Password Recovery

`ilikephp` + salt `GZ` from hash → `crypt("ilikephp", "GZ")` matches `GZKc.2/VQffio`. **But `ilikephp` was submitted to WeChall and REJECTED.**

### access.log (id 46)
```
<timestamp> <client_ip>:<client_port>
```
Changes every connection. Single line.

### mail spool (id 88) — BACKDOOR HINT
```
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```

### Hidden Entry: id 256

Using additive encoding (256 = 128+128):
- `name(256)` → `wtf`
- `readfile(256)` → `Uhm... yeah... no...\n`
- `readdir(256)` → Right(4) "Not a directory"
- Not reachable from directory tree
- Scanned 257–1024: no additional IDs found

## Key Observations

- No interactive shell syscall exists; /bin/sh, /bin/sudo, /bin/false are all 0-byte files
- BrownOS is a functional VM + virtual filesystem, not a real OS shell
- There is no way to "log in" or "execute commands" — only syscall-based operations
