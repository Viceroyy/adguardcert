#!/system/bin/sh

exec > /data/local/tmp/adguardcert.log
exec 2>&1

set -x

MODDIR=${0%/*}

set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd $1 | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R $selinux_context $2
    else
        chcon -R $default_selinux_context $2
    fi
}

# Wait for the zygote64 process to start
while [ -z "$(pidof zygote64)" ]; do
    sleep 1
done

# Android hashes the subject to get the filename, field order is significant.
# (`openssl x509 -in ... -noout -hash`)
# AdGuard's certificate is "/C=EN/O=AdGuard/CN=AdGuard Personal CA".
# The filename is then <hash>.<n> where <n> is an integer to disambiguate
# different certs with the same hash (e.g. when the same cert is installed repeatedly).
# 
# Due to https://github.com/AdguardTeam/AdguardForAndroid/issues/2108
# 1. Retrieve the most recent certificate with our hash from the user store.
#    It is assumed that the last installed AdGuard's cert is the correct one.
# 2. Copy the AdGuard certificate to the system store under the name "<hash>.0". 
#    Note that some apps may ignore other certs.
# 3. Remove all certs with our hash from the `cacerts-removed` directory.
#    They get there if a certificate is "disabled" in the security settings.
#    Apps will reject certs that are in the `cacerts-removed`.
AG_CERT_HASH=0f4ed297
AG_CERT_FILE=$(ls /data/misc/user/*/cacerts-added/${AG_CERT_HASH}.* | (IFS=.; while read -r left right; do echo $right $left.$right; done) | sort -nr | (read -r left right; echo $right))

if ! [ -e "${AG_CERT_FILE}" ]; then
    exit 0
fi

rm -f /data/misc/user/*/cacerts-removed/${AG_CERT_HASH}.*

cp -f ${AG_CERT_FILE} ${MODDIR}/system/etc/security/cacerts/${AG_CERT_HASH}.0
chown -R 0:0 ${MODDIR}/system/etc/security/cacerts
set_context /system/etc/security/cacerts ${MODDIR}/system/etc/security/cacerts

# Android 14 support
# Since Magisk ignores /apex for module file injections, use a non-Magisk way
if [ -d /apex/com.android.conscrypt/cacerts ]; then
    # Define a temporary directory for handling certificates
    TEMP_DIR=/data/local/tmp/adg-ca-copy

    # Ensure the temporary directory is clean before use
    # Changed from `rm -f` to `rm -rf` to handle potential directory remnants
    rm -rf $TEMP_DIR
    mkdir -p $TEMP_DIR

    # Clone the APEX CA directory into tmpfs to allow modifications
    mount -t tmpfs tmpfs $TEMP_DIR
    cp -f /apex/com.android.conscrypt/cacerts/* $TEMP_DIR/

    # Add the AdGuard certificate to the temporary directory
    cp -f ${AG_CERT_FILE} $TEMP_DIR/${AG_CERT_HASH}.0
    chown -R 0:0 $TEMP_DIR

    # Apply SELinux context to the temporary directory
    set_context /apex/com.android.conscrypt/cacerts $TEMP_DIR

    # Count the number of certificates in the temporary directory
    CERTS_NUM="$(ls -1 $TEMP_DIR | wc -l)"
    if [ "$CERTS_NUM" -gt 10 ]; then
        # If valid, replace the APEX CA directory with the temporary one
        mount --bind $TEMP_DIR /apex/com.android.conscrypt/cacerts
        for pid in 1 $(pgrep zygote) $(pgrep zygote64); do
            # Apply the mount to all necessary namespaces
            nsenter --mount=/proc/${pid}/ns/mnt -- \
                /bin/mount --bind $TEMP_DIR /apex/com.android.conscrypt/cacerts
        done
    else
        # Safety check: Abort if the certificate count is suspiciously low
        echo "Cancelling replacing CA storage due to safety"
    fi

    # Ensure the temporary directory is unmounted and cleaned up properly
    # Added a loop to handle cases where unmounting may be delayed
    while ! umount $TEMP_DIR; do
        echo "Temporary storage still in use. Retrying unmount..."
        sleep 1
    done
    rmdir $TEMP_DIR
fi
