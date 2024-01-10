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

inbc source application add --filename $CHROME_SOURCES_FILE --sources \"Enabled: yes\" \"Types: deb\" \"URIs: http://dl.google.com/linux/chrome/deb/\" \"Suites: stable\" \"Components: main\"

if [ ! -e "/etc/apt/sources.list.d/$CHROME_SOURCES_FILE" ]; then
    echo "Error: The file '/etc/apt/sources.list.d/$CHROME_SOURCES_FILE' does not exist!"
    exit 1
fi
inbc source application remove --filename "$CHROME_SOURCES_FILE"

if inbc source application list 2>&1 | grep -q "$OPERA_KEY_NAME"; then
    echo "Error: $OPERA_KEY_NAME should not be present in the application list after removal"
    exit 1
fi

if inbc source application list 2>&1 | grep -q "$CHROME_SOURCES_FILE"; then
    echo "Error: $CHROME_SOURCES_FILE should not be present in the application list after removal"
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
