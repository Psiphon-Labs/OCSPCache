#!/usr/bin/awk -f
#
# Take a PEM format file as input and split out certs and keys into separate files
#
# Example:
#   
#   openssl s_client -showcerts -connect www.google.com:443 < /dev/null > tst.der
#
#   ./pem-split.sh ./tst.der
#
# Credit to: https://gist.github.com/jinnko/d6867ce326e8b6e88975

BEGIN                          { n=0; cert=0; if ( ARGC < 2 ) { print "Usage: pem-split FILENAME"; exit 1 } }
split_after == 1               { n++; split_after=0 }
/-----BEGIN CERTIFICATE-----/  { cert=1 }
cert == 1                      { filename=sprintf("%s%d%s", "cert", n, ".pem"); print > filename }
/-----END CERTIFICATE-----/    { split_after=1; cert=0 }
