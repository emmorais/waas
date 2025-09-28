#!/bin/bash

# Test script to demonstrate the storage optimization

echo "🧪 Testing TSS Protocol Storage Optimization"
echo "==========================================="

# Clean up any existing storage files
echo "🧹 Cleaning up existing storage files..."
rm -f keygen_completed.marker keygen_essential.json auxinfo_completed.marker presign_completed.marker public_key.bin

echo "📊 Testing first run (should run all protocols)..."
echo "Expected: Full protocol execution (keygen + auxinfo + presign)"

# Note: You would need to start the server and make a signing request here
# This is just a demonstration of the concept

echo ""
echo "📊 Testing second run (should skip protocols and use storage)..."
echo "Expected: Fast execution using stored results"

echo ""
echo "🔍 Storage files that will be created after first run:"
echo "- keygen_completed.marker (indicates keygen was completed)"
echo "- keygen_essential.json (stores public key and chain code)"
echo "- auxinfo_completed.marker (indicates auxinfo was completed)"  
echo "- presign_completed.marker (indicates presign was completed)"
echo "- public_key.bin (stores public key for verification)"

echo ""
echo "⚡ Performance improvement: Subsequent signing operations will be much faster!"
echo "   - First run: Full protocol execution (~expensive)"
echo "   - Later runs: Skip expensive protocols, only run actual signing (~fast)"
