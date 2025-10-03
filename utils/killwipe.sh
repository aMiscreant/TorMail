#!/bin/bash

GPG_HOME="$HOME/.tormail_keys"

echo "[!] Overwriting and wiping $GPG_HOME"
shred -uzn 3 "$GPG_HOME/random_seed" 2>/dev/null
rm -rf "$GPG_HOME"

echo "[✔] GPG home wiped"
