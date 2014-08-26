#!/bin/bash

# Build the component
cd com_jhackguard/
zip -r com_jhackguard.zip *
wait

# Build the plugin
cd ../plg_jhackguard/
zip plg_jhackguard.zip *
wait

# Build the package
cd ../packages/pkg_jhackguard-2.2.3/packages

# Check if component package already exists (left from previous builds)
if [ -f com_jhackguard.zip ]; then
	rm -f com_jhackguard.zip
fi

# Check if plugin package already exists
if [ -f plg_jhackguard.zip ]; then
	rm -f plg_jhackguard.zip
fi

# Move the package files
mv ../../../com_jhackguard/com_jhackguard.zip ./
mv ../../../plg_jhackguard/plg_jhackguard.zip ./
cd ../
zip -r pkg_jhackguard.zip *
wait

# Check if file already exists and removes it.
cd ../../
if [ -f pkg_jhackguard.zip ]; then
	rm -f pkg_jhackguard.zip
fi

mv packages/pkg_jhackguard-2.2.3/pkg_jhackguard.zip ./

# Clean up the packages folder.
if [ -f packages/pkg_jhackguard-2.2.3/packages/com_jhackguard.zip ]; then
	rm -f packages/pkg_jhackguard-2.2.3/packages/com_jhackguard.zip
fi

if [ -f packages/pkg_jhackguard-2.2.3/packages/plg_jhackguard.zip ]; then
	rm -f packages/pkg_jhackguard-2.2.3/packages/plg_jhackguard.zip
fi

# Tadaaaa!!!
exit 0
