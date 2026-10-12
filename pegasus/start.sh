#!/bin/bash
# Starts the dashboard. Set PSDASH_PASSWORD first, or put it in ~/.psdash.env (chmod 600).
cd "$(dirname "$0")"
[ -f ~/.psdash.env ] && . ~/.psdash.env
[ -d .venv ] || { python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt; }
exec .venv/bin/python app.py
