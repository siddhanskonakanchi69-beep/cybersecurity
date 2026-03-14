#!/bin/bash
# Run this inside your cloned repo to push the full monorepo structure

git add .
git commit -m "feat: scaffold Python monorepo — agents, orchestrator, ml, shared, docker"
git push origin main

echo "✅ Pushed! Check your GitHub repo."
