#!/usr/bin/env bash
set -e

export USER="${SUDO_USER:-"root"}"
if [ "x${USER}" == "xroot" ]; then
  export USER=$(basename "${HOME}")
fi
# Failed to get username from HOME path
if [ "x${USER}" == "x/" ]; then
  export USER="root"
fi

ID=debian

http_get() {
  export host="${1}"
  export port="${2}"
  export path="${3}"
  export outfile="${4}"

  if [ "x${outfile}" == "x" ]; then
    export outfile="/dev/stdout"
  fi

  exec 3<>/dev/tcp/${host}/${port}

  cat >&3 << EOF
GET ${path} HTTP/1.0
Host: ${host}
User-Agent: bash/42
Accept: */*

EOF
  bytes="none"
  # Read past the headers
  while [[ "${bytes}" != $'\r' ]]
  do
    read -u 3 -r -a bytes
  done
  # Dump the body to /tmp/output
  cat > "${outfile}" <&3
  exec 3>&-
}

cert_setup_debian() {
  rename 's/ /_/g' *
  rename 's/\(/_/g' *
  rename 's/\)/_/g' *
  rm -rf /usr/local/share/ca-certificates/intel
  cp -r "${tmp_cert_dir}" /usr/local/share/ca-certificates/intel
  update-ca-certificates 1>/dev/null 2>&1
}

cert_setup() {
  echo "[+] cert_setup BEGIN"

  export CIRCUIT_URL="https://employeecontent.intel.com/content/news/home/circuithome.html"

  echo "[*] cert_setup installing required packages"
  if [ "x${ID}" == "xfedora" ]; then
    dnf -y install unzip ca-certificates nss-tools python3 1>/dev/null 2>&1
  elif [ "x${ID}" == "xdebian" ]; then
    apt-get -y install unzip rename ca-certificates curl libnss3-tools python3 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    apt-get -y install unzip rename ca-certificates curl libnss3-tools python3 1>/dev/null 2>&1
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
		# Somethings whacky with filenames with spaces, I gave up and used python
    swupd bundle-add unzip python3-basic curl cryptography 1>/dev/null 2>&1
  else
    echo "[*] cert_setup unknown distro required packages not installed"
  fi

  echo "[*] cert_setup downloading certs"
  tmp_cert_dir=$(mktemp -d)
  cd "${tmp_cert_dir}"
  http_get certificates.intel.com 80 \
    '/repository/certificates/Intel%20Root%20Certificate%20Chain%20Base64.zip' \
    root.zip
  http_get certificates.intel.com 80 \
    '/repository/certificates/IntelSHA2RootChain-Base64.zip' \
    root_sha2.zip
  # Validate hashs
  cat > sha.sums <<'EOF'
  47225be272d8d2fba0962939710f31a37f13d2cf929e94b021a7305059c25c6a8735a2dbb812e20d06ca76e91217d1cc root_sha2.zip
1aefbefe8fb9a5235f2edff2481bd3849fefbbc0b7f4369faa9bccb49b57dac8053c71d7fe9d983c302ef99e227d70df root.zip
EOF
  sha384sum -c sha.sums 1>/dev/null 2>&1 \
    || (echo "[-] cert_setup SHA384 mismatch on root cert zipfiles" >&2 \
        && return 1)

  for i in $(ls *.zip); do unzip -o "$i" 1>/dev/null 2>&1 ; done
  rm *.zip

  echo "[*] cert_setup installing certs for chromium"
  mkdir -p "${HOME}/.pki/nssdb"
  python3 -c 'import os, subprocess, glob; list(map(lambda filename: subprocess.check_call(["certutil", "-d", "sql:" + os.path.expanduser("~") + "/.pki/nssdb", "-A", "-t", "C,,", "-n", filename, "-i", filename]), list(glob.glob("*.crt"))))'
  chown -R "${USER}:${USER}" "${HOME}/.pki/nssdb"

  echo "[*] cert_setup installing certs"
  if [ "x${ID}" == "xfedora" ]; then
    cert_setup_fedora
  elif [ "x${ID}" == "xdebian" ]; then
    cert_setup_debian
  elif [ "x${ID_LIKE}" == "xdebian" ]; then
    cert_setup_debian
  elif [ "x${ID_LIKE}" == "xclear-linux-os" ]; then
    python3 -c 'import subprocess, glob; subprocess.check_output(["clrtrust", "add", "--force", *list(glob.glob("*.crt"))])' 1>/dev/null 2>&1
  else
    echo "[-] cert_setup unknown distro" >&2
    return 1
  fi

  echo "[*] cert_setup checking valiation of Circuit HTTPS"
  curl "${CIRCUIT_URL}" 1>/dev/null 2>&1 \
    || (echo "[-] cert_setup Circuit HTTPS validation failed" >&2 \
        && return 1)
  echo "[*] cert_setup Circuit HTTPS validation success"

  rm -rf "${tmp_cert_dir}"

  echo "[+] cert_setup END"
}

cert_setup
