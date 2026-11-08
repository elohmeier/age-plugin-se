# Unlock agent

Keys generated with `--access-control application-password` are protected by a password of
your choice, which the Secure Enclave checks. To avoid entering it for every decryption, run
the agent: it keeps the keys unlocked after a single unlock, until it stops (logout/reboot),
`age-plugin-se lock` is run, the optional `--timeout` expires, or (optionally) the system
sleeps or the screen locks.

The private key never leaves the Secure Enclave. The agent only keeps an `LAContext` holding
the password, and performs key agreements with it on behalf of the plug-in.

Anything running as your user can use an unlocked key through the agent, just like with
`gpg-agent` or `ssh-agent`. Without the password, the key cannot be used at all, also not by
code running as your user; on another machine, it cannot be used even with the password.

## Usage

```
$ age-plugin-se keygen --access-control application-password --recipient-type tag \
    -o ~/.passage/identities
Enter a password to protect the new key
Password:
Confirm the password
Confirm:
Public key: age1tag1q…
$ age-plugin-se agent &          # or as a LaunchAgent, see below
$ age -d -i ~/.passage/identities secret.age
Enter the password for age1tag1q…: ********
…
$ age -d -i ~/.passage/identities secret.age       # no prompt
```

`age-plugin-se unlock -i ~/.passage/identities` unlocks the keys up front, asking on the
terminal, or with pinentry (`$PINENTRY_PROGRAM`, default `pinentry-mac`) when there is no
terminal. This is useful for clients that cannot ask for a password (e.g. GUI apps), for
example from a login item.

LaunchAgent (`~/Library/LaunchAgents/age-plugin-se-agent.plist`):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>age-plugin-se-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/age-plugin-se</string>
    <string>agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

Post-quantum keys cannot be protected by an application password: the Secure Enclave refuses
ML-KEM operations on such keys.

## Identity format

Application password identities are `AGE-PLUGIN-SE-1…` identities whose data is the 4-byte
marker `00 00 70 77` followed by the Secure Enclave key blob. The marker cannot be confused with
a key blob, nor with the post-quantum container (whose first length field is never 0). Older
versions of the plug-in reject these identities.

## Protocol

- Unix stream socket, one request and one response per connection, each a single line of JSON
  terminated by `\n`.
- Socket path: `--socket`, else `$AGE_PLUGIN_SE_AGENT_SOCK`, else
  `~/Library/Application Support/age-plugin-se/agent.sock`. The agent creates the directory
  `0700` and the socket `0600`, and rejects peers with a different UID (`getpeereid`). Both the
  agent and the plug-in refuse a directory that is not owned by the current user, or is
  writable by others.
- The plug-in uses the agent when it answers a `status` request, and `AGE_PLUGIN_NO_AGENT` is
  not set. Otherwise, it asks for the password once per run.

All binary values are standard base64 with padding. `key` is the Secure Enclave key blob.

| Request | Success response |
|---|---|
| `{"op":"status"}` | `{"ok":true,"unlocked":<int>}` |
| `{"op":"lock"}` | `{"ok":true}` |
| `{"op":"unlock","key":K,"password":P}` | `{"ok":true}`. The agent checks P with a key agreement against a random P-256 point before keeping it. |
| `{"op":"ecdh","key":K,"share":S}` | `{"ok":true,"secret":X}`. X is the raw P-256 ECDH shared secret (x-coordinate); S is an uncompressed (65-byte) P-256 point. |

Error response: `{"ok":false,"error":E,"message":"…"}`, where E is `locked` (the plug-in asks
for the password through age, sends `unlock`, and retries), `bad-password`, `invalid`, or
`internal`.

The same protocol is implemented by the TPM agent of the age-plugin-tpm fork, where `key` is
the TPM identity.
