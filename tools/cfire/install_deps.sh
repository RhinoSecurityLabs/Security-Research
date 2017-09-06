#!/bin/sh

echo "Clone Sublist3r into lib directory."
git clone https://github.com/aboul3la/Sublist3r.git lib/Sublist3r

echo "Clone subbrute into lib directory."
git clone https://github.com/TheRook/subbrute.git lib/subbrute

echo "Finalizing deps install"
touch lib/Sublist3r/__init__.py
touch lib/subbrute/__init__.py
