#!/bin/bash

# Some fancy vars here :)
ESC="\x1b["
GREEN=$ESC"32;01m"
DBLUE=$ESC"34;01m"
WHITE=$ESC"37;01m"
RESET=$ESC"39;49;00m"


function show_info {
        echo -e "${GREEN}[${WHITE}+${GREEN}]${DBLUE} ${1}:${GREEN} ${2}${RESET}"
}


# Build the component
cd com_jhackguard/
zip -qr com_jhackguard.zip *
wait
show_info "Creating component archive" "Done"


# Build the plugin
cd ../plg_jhackguard/
zip -qr plg_jhackguard.zip *
wait;
show_info "Creating plugin archive" "Done"


# Build the package
cd ../packages/pkg_jhackguard-2.2.3/packages
wait;

# Check if component package already exists (left from previous builds)
if [ -f com_jhackguard.zip ]; then
	rm -f com_jhackguard.zip
	show_info "Removing previous version component archive" "Done"
fi
wait;

# Check if plugin package already exists
if [ -f plg_jhackguard.zip ]; then
	rm -f plg_jhackguard.zip
	show_info "Removing previous version plugin archive" "Done"
fi
wait;

# Move the package files
mv ../../../com_jhackguard/com_jhackguard.zip ./
mv ../../../plg_jhackguard/plg_jhackguard.zip ./
cd ../
zip -qr pkg_jhackguard.zip *
show_info "Creating package archive" "Done"
wait;

# Check if file already exists and removes it.
cd ../../
if [ -f pkg_jhackguard.zip ]; then
	rm -f pkg_jhackguard.zip
	show_info "Removing previous package archive" "Done"
fi
wait;

mv packages/pkg_jhackguard-2.2.3/pkg_jhackguard.zip ./
show_info "Copying package archive to root" "Done"

# Clean up the packages folder.
if [ -f packages/pkg_jhackguard-2.2.3/packages/com_jhackguard.zip ]; then
	rm -f packages/pkg_jhackguard-2.2.3/packages/com_jhackguard.zip
fi

if [ -f packages/pkg_jhackguard-2.2.3/packages/plg_jhackguard.zip ]; then
	rm -f packages/pkg_jhackguard-2.2.3/packages/plg_jhackguard.zip
fi
show_info "Cleaning up" "Done"
# Tadaaaa!!!
exit 0
