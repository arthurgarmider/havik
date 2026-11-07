#!/bin/sh
# Reads the version it wants and downloads that release; nothing goes out.
version=$(cat ~/.config/tool/version)
curl -f -D headers.txt -o tool.tgz "https://downloads.example.com/tool-$version.tgz"
wget -t 3 -T 10 https://downloads.example.com/tool.sha256
