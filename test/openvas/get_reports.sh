#!/bin/sh

OMP_USER="admin"
OMP_PASS=""
WEBHOOK_URL="https://api.fortmesa.com/...."


REPORTS=$(omp -u "${OMP_USER}" -w "${OMP_PASS}" -G --details | awk ' BEGIN { cmd = "date +%s"; cmd | getline epoch; today=(epoch-(86400)); } /^  [a-fA-F0-9]/ { gsub("Z","",$7); cmd = "date +%s -d " $7; cmd | getline epoch; if(epoch>today) { print $1 }; }')

OMP_XML=$(omp -u "${OMP_USER}" -w "${OMP_PASS}" -F | awk '/^[a-fA-F0-9\-]+ +XML$/ { print $1; }')

echo "${REPORTS}" | while read  line; do
  if [ ! -z "${line}" ]; then
    omp -u "${OMP_USER}" -w "${OMP_PASS}" -R "${line}" -f "${OMP_XML}" | node openvas.js "${WEBHOOK_URL}"
  fi
done


