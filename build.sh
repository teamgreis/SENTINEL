#!/usr/bin/env bash
# Baut SENTINEL und packt die Windows-.exe nach /opt/data/Sentinel/dist
set -euo pipefail

export DOTNET_ROOT=/opt/data/dotnet
export PATH="/opt/data/dotnet:$PATH"
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1   # ICU fehlt im Container

REPO="/opt/data/sentinel"
DIST="/opt/data/Sentinel/dist/SENTINEL-win-x64"

cd "$REPO"

echo "== Tests =="
dotnet test tests/Sentinel.Tests/Sentinel.Tests.csproj

echo "== Publish (win-x64, self-contained) =="
rm -rf "$DIST"
dotnet publish src/Sentinel.App/Sentinel.App.csproj \
    -p:EnableWindowsTargeting=true \
    -c Release -r win-x64 --self-contained true \
    -o "$DIST"

echo "== Fertig =="
echo "Exe: $DIST/Sentinel.exe"
