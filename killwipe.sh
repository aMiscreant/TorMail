#!/usr/bin/env bash
# aMiscreant
# For testing purposes.

GPG_HOME="$HOME/.tormail_keys"
TOR_MAIL_HOME="$HOME/.tormail/"

echo "[!] Overwriting and wiping $GPG_HOME"
shred -uzn 3 "$GPG_HOME/random_seed" 2>/dev/null
rm -rf "$GPG_HOME"

echo "[!] Overwriting and wiping $TOR_MAIL_HOME"
shred -uzn 3 "$TOR_MAIL_HOME/random_seed" 2>/dev/null
rm -rf "$TOR_MAIL_HOME"

echo "[ok!] GPG home wiped"
echo "[ok!] tormail home wiped"