#!/bin/bash
set -e
set -x

source /scripts/test_util.sh

trap 'kill -9 $(jobs -p) || true' EXIT

APT_SOURCES="/etc/apt/sources.list"
BAK_APT_SOURCES="$APT_SOURCES.bak"
FAKE_SOURCE="deb test123"
UPDATE_SOURCE1="deb test456"
UPDATE_SOURCE2="deb test789"
OPERA_KEY_URI="https://deb.opera.com/archive.key"
OPERA_KEY_NAME="opera.gpg"
OPERA_SOURCES="deb [arch=amd64 signed-by=/usr/share/keyrings/$OPERA_KEY_NAME] https://deb.opera.com/opera-stable/ stable non-free"
OPERA_LIST="opera.list"
NEW_APP_SOURCE="deb newsource"
CHROME_SOURCES_FILE="google-chrome.sources"
CHROME_DEB_822=("Enabled: yes" "Types: deb" "URIs: http://dl.google.com/linux/chrome/deb/" "Suites: stable" "Components: main" "Signed-By:" " -----BEGIN PGP PUBLIC KEY BLOCK-----" " Version: GnuPG v1.4.2.2 (GNU/Linux)" " ." " mQGiBEXwb0YRBADQva2NLpYXxgjNkbuP0LnPoEXruGmvi3XMIxjEUFuGNCP4Rj/a" " kv2E5VixBP1vcQFDRJ+p1puh8NU0XERlhpyZrVMzzS/RdWdyXf7E5S8oqNXsoD1z" " fvmI+i9b2EhHAA19Kgw7ifV8vMa4tkwslEmcTiwiw8lyUl28Wh4Et8SxzwCggDcA" " feGqtn3PP5YAdD0km4S4XeMEAJjlrqPoPv2Gf//tfznY2UyS9PUqFCPLHgFLe80u" " QhI2U5jt6jUKN4fHauvR6z3seSAsh1YyzyZCKxJFEKXCCqnrFSoh4WSJsbFNc4PN" " b0V0SqiTCkWADZyLT5wll8sWuQ5ylTf3z1ENoHf+G3um3/wk/+xmEHvj9HCTBEXP" " 78X0A/0Tqlhc2RBnEf+AqxWvM8sk8LzJI/XGjwBvKfXe+l3rnSR2kEAvGzj5Sg0X" " 4XmfTg4Jl8BNjWyvm2Wmjfet41LPmYJKsux3g0b8yzQxeOA4pQKKAU3Z4+rgzGmf" " HdwCG5MNT2A5XxD/eDd+L4fRx0HbFkIQoAi1J3YWQSiTk15fw7RMR29vZ2xlLCBJ" " bmMuIExpbnV4IFBhY2thZ2UgU2lnbmluZyBLZXkgPGxpbnV4LXBhY2thZ2VzLWtl" " eW1hc3RlckBnb29nbGUuY29tPohjBBMRAgAjAhsDBgsJCAcDAgQVAggDBBYCAwEC" " HgECF4AFAkYVdn8CGQEACgkQoECDD3+sWZHKSgCfdq3HtNYJLv+XZleb6HN4zOcF" " AJEAniSFbuv8V5FSHxeRimHx25671az+uQINBEXwb0sQCACuA8HT2nr+FM5y/kzI" " A51ZcC46KFtIDgjQJ31Q3OrkYP8LbxOpKMRIzvOZrsjOlFmDVqitiVc7qj3lYp6U" " rgNVaFv6Qu4bo2/ctjNHDDBdv6nufmusJUWq/9TwieepM/cwnXd+HMxu1XBKRVk9" " XyAZ9SvfcW4EtxVgysI+XlptKFa5JCqFM3qJllVohMmr7lMwO8+sxTWTXqxsptJo" " pZeKz+UBEEqPyw7CUIVYGC9ENEtIMFvAvPqnhj1GS96REMpry+5s9WKuLEaclWpd" " K3krttbDlY1NaeQUCRvBYZ8iAG9YSLHUHMTuI2oea07Rh4dtIAqPwAX8xn36JAYG" " 2vgLAAMFB/wKqaycjWAZwIe98Yt0qHsdkpmIbarD9fGiA6kfkK/UxjL/k7tmS4Vm" " CljrrDZkPSQ/19mpdRcGXtb0NI9+nyM5trweTvtPw+HPkDiJlTaiCcx+izg79Fj9" " KcofuNb3lPdXZb9tzf5oDnmm/B+4vkeTuEZJ//IFty8cmvCpzvY+DAz1Vo9rA+Zn" " cpWY1n6z6oSS9AsyT/IFlWWBZZ17SpMHu+h4Bxy62+AbPHKGSujEGQhWq8ZRoJAT" " G0KSObnmZ7FwFWu1e9XFoUCt0bSjiJWTIyaObMrWu/LvJ3e9I87HseSJStfw6fki" " 5og9qFEkMrIrBCp3QGuQWBq/rTdMuwNFiEkEGBECAAkFAkXwb0sCGwwACgkQoECD" " D3+sWZF/WACfeNAu1/1hwZtUo1bR+MWiCjpvHtwAnA1R3IHqFLQ2X3xJ40XPuAyY" " /FJG" " %20=Quqp" " -----END PGP PUBLIC KEY BLOCK-----")

cp "$APT_SOURCES" "$BAK_APT_SOURCES"

test_failed() {
    cp "$BAK_APT_SOURCES" "$APT_SOURCES"
    rm -f "/usr/share/keyrings/$OPERA_KEY_NAME"
    rm -f "/etc/apt/sources.list.d/$OPERA_LIST"
    echo "Return code: $?"
    echo "TEST FAILED!!!"
}
trap test_failed ERR

echo "Starting source test." | systemd-cat

# OS tests
inbc source os add --sources "$FAKE_SOURCE"
grep "$FAKE_SOURCE" "$APT_SOURCES"
inbc source os list 2>&1 | grep "$FAKE_SOURCE"
inbc source os remove --sources "$FAKE_SOURCE"
grep "$FAKE_SOURCE" "$APT_SOURCES" && exit 1

inbc source os add --sources "$FAKE_SOURCE"
inbc source os update --sources "$UPDATE_SOURCE1" "$UPDATE_SOURCE2"
grep "$FAKE_SOURCE" "$APT_SOURCES" && exit 1
grep "$UPDATE_SOURCE1" "$APT_SOURCES"
grep "$UPDATE_SOURCE2" "$APT_SOURCES"

cp "$BAK_APT_SOURCES" "$APT_SOURCES"

# Application tests
rm -f "/usr/share/keyrings/$OPERA_KEY_NAME"
rm -f "/etc/apt/sources.list.d/$OPERA_LIST"
inbc source application add --gpgKeyUri "$OPERA_KEY_URI" --gpgKeyName "$OPERA_KEY_NAME" --sources "$OPERA_SOURCES" --filename "$OPERA_LIST"
if [ ! -e "/usr/share/keyrings/$OPERA_KEY_NAME" ]; then
    echo "Error: The file '/usr/share/keyrings/$OPERA_KEY_NAME' does not exist!"
    exit 1
fi
inbc source application list 2>&1 | grep "$OPERA_KEY_NAME"
inbc source application remove --gpgKeyName "$OPERA_KEY_NAME" --filename "$OPERA_LIST"

inbc source application add --filename $CHROME_SOURCES_FILE --sources \"Enabled: yes\" \"Types: deb\" \"URIs: http://dl.google.com/linux/chrome/deb/\" \"Suites: stable\" \"Components: main\""

if [ ! -e "/etc/apt/sources.list.d/$CHROME_SOURCES" ]; then
    echo "Error: The file '/etc/apt/sources.list.d/$CHROME_SOURCES' does not exist!"
    exit 1
fi

if inbc source application list 2>&1 | grep -q "$OPERA_KEY_NAME"; then
    echo "Error: $OPERA_KEY_NAME should not be present in the application list after removal"
    exit 1
fi

inbc source application add --gpgKeyUri "$OPERA_KEY_URI" --gpgKeyName "$OPERA_KEY_NAME" --sources "$OPERA_SOURCES" --filename "$OPERA_LIST"

inbc source application update --sources "$NEW_APP_SOURCE" --filename "$OPERA_LIST"
inbc source application list 2>&1 | grep "$NEW_APP_SOURCE"

if inbc source application list 2>&1 | grep -q "$OPERA_KEY_NAME"; then
    echo "Error: $OPERA_KEY_NAME should not be present in the application list after update"
    exit 1
fi
inbc source application remove --gpgKeyName "$OPERA_KEY_NAME" --filename "$OPERA_LIST"
rm -f "/usr/share/keyrings/$OPERA_KEY_NAME"
rm -f "/etc/apt/sources.list.d/$OPERA_LIST"
