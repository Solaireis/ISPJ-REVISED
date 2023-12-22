#!/bin/bash

# Convert all .png and .jpg files in the current directory to .webp
# For windows user, please use WSL to run this script.
# Also ignore any images in any subfolder called "original"
find ./ -type f \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jfif" \) -not -path "./**/original/*" -exec sh -c 'cwebp -q 80 $1 -o "${1%.*}.webp"' _ {} \;