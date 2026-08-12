#!/bin/bash

echo "🚀 Deploying BOUGG to GitHub..."

cd ~/Projects/Bougg/render-deploy

# Check if git is initialized
if [ ! -d .git ]; then
    echo "📁 Initializing git..."
    git init
fi

# Remove existing remote if any
git remote remove origin 2>/dev/null

# Add correct remote
git remote add origin https://github.com/AswaGhosh1/bougg-render.git

# Add all files
git add .

# Commit
git commit -m "BOUGG Malware Detection Tool with VirusTotal integration"

# Rename branch to main if needed
git branch -M main

# Push
git push -u origin main

echo "✅ Deployment complete!"
echo "🌐 Your repository: https://github.com/AswaGhosh1/bougg-render"
