#!/bin/sh
set -e

REALM="EXAMPLE.ORG"

if [ ! -f /var/lib/krb5kdc/principal ]; then
    kdb5_util create -s -r "$REALM" -P masterkey
    # +no_auth_data_required stops the KDC from including a PAC in service
    # tickets: the gokrb5-based SPNEGO service in yunikorn-core cannot decode
    # the minimal (non-AD) PAC that MIT krb5 >= 1.20 issues by default
    kadmin.local -q "addprinc -randkey +no_auth_data_required HTTP/localhost@$REALM"
    kadmin.local -q "ktadd -k /var/keytabs/service.keytab HTTP/localhost@$REALM"
    kadmin.local -q "addprinc -pw admin1pw admin1@$REALM"
    kadmin.local -q "addprinc -pw viewer1pw viewer1@$REALM"
    kadmin.local -q "addprinc -pw alicepw alice@$REALM"
fi

exec krb5kdc -n
