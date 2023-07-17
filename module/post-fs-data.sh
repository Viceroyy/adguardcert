#!/system/bin/sh
MODDIR=${0%/*}

# Android hashes the subject to get the filename, field order is significant.
# (`openssl x509 -in ... -noout -hash`)
# AdGuard's primary certificate is "/C=EN/O=AdGuard/CN=AdGuard Personal CA".
# AdGuard's intermediate certificate is "/C=EN/O=AdGuard/CN=AdGuard Personal Intermediate".
# The filename is then <hash>.<n> where <n> is an integer to disambiguate
# different certs with the same hash (e.g. when the same cert is installed repeatedly).
# 
# Due to https://github.com/AdguardTeam/AdguardForAndroid/issues/2108
# 1. Retrieve the most recent primary and intermediate certificates with our hash from the user store.
#    It is assumed that the last installed AdGuard's certs are the correct ones.
# 2. Check the existence of AdGuard's intermediate certificate. If the certificate is not present, 
#    the steps 3 and 4 will be skipped.
# 3. Copy the primary AdGuard certificate to the system store under the name "<hash>.0". 
#    Note that some apps may ignore other certs.
# 4. Remove all certs with our hash from the `cacerts-removed` directory.
#    They get there if a certificate is "disabled" in the security settings.
#    Apps will reject certs that are in the `cacerts-removed`.
AG_CERT_HASH=0f4ed297
AG_INTERMEDIATE_CERT_HASH=47ec1af8
AG_CERT_FILE=$(ls /data/misc/user/*/cacerts-added/${AG_CERT_HASH}.* | (IFS=.; while read -r left right; do echo $right $left.$right; done) | sort -nr | (read left right; echo $right))
AG_INTERMEDIATE_CERT_FILE=$(ls /data/misc/user/*/cacerts-added/${AG_INTERMEDIATE_CERT_HASH}.* | (IFS=.; while read -r left right; do echo $right $left.$right; done) | sort -nr | (read left right; echo $right))

if [ -e "${AG_CERT_FILE}" ] && [ -e "${AG_INTERMEDIATE_CERT_FILE}" ]; then
    cp -f ${AG_CERT_FILE} ${MODDIR}/system/etc/security/cacerts/${AG_CERT_HASH}.0
    rm -f /data/misc/user/*/cacerts-removed/${AG_CERT_HASH}.*
fi

chown -R 0:0 ${MODDIR}/system/etc/security/cacerts

[ "$(getenforce)" = "Enforcing" ] || exit 0

default_selinux_context=u:object_r:system_file:s0
selinux_context=$(ls -Zd /system/etc/security/cacerts | awk '{print $1}')

if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
    chcon -R $selinux_context $MODDIR/system/etc/security/cacerts
else
    chcon -R $default_selinux_context $MODDIR/system/etc/security/cacerts
fi
