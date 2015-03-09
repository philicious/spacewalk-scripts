#!/bin/bash
#
# Creates the Release and Release.gpg files for APT repo
# based on Packages and Packages.gz files
# The created files make the repo a "signed" repo

DATE=`date "+%a, %d %b %Y %H:%M:%S %z"`
GPG_PASS='foobar'

HEADER="Origin: Ubuntu
Label: Ubuntu
Suite: precise
Version: 12.04
Codename: precise
Date: ${DATE}
Architectures: amd64
Components: repodata
Description: Ubuntu Precise 12.04
MD5Sum:"

PACKAGES_MD5=($(md5sum Packages))
PACKAGES_SIZE=$(stat -c%s Packages)
PACKAGESGZ_MD5=($(md5sum Packages.gz))
PACKAGESGZ_SIZE=$(stat -c%s Packages.gz)
PACKAGES_SHA256=($(sha256sum Packages))
PACKAGESGZ_SHA256=($(sha256sum Packages.gz))

# write Release file with MD5s
rm -rf Release
echo -e "${HEADER}" > Release
echo -e " ${PACKAGES_MD5}\t${PACKAGES_SIZE}\trepodata/binary-amd64/Packages" >> Release
echo -e " ${PACKAGESGZ_MD5}\t${PACKAGESGZ_SIZE}\trepodata/binary-amd64/Packages.gz" >> Release
echo -e "SHA256:" >> Release
echo -e " ${PACKAGES_SHA256}\t${PACKAGES_SIZE}\trepodata/binary-amd64/Packages" >> Release
echo -e " ${PACKAGESGZ_SHA256}\t${PACKAGESGZ_SIZE}\trepodata/binary-amd64/Packages.gz" >> Release

# write the signature for Release file
rm -rf Release.gpg
echo $GPG_PASS | gpg --armor --detach-sign -o Release.gpg --batch --no-tty --passphrase-fd 0 --sign Release