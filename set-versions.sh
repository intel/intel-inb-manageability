set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo WARNING, this will clean and reset the repository in "$DIR"
echo Waiting 5 seconds... hit control-C to abort.
sleep 5

NEW_VERSION=$1

cd "$DIR"
git clean -xdf
git reset --hard

OLD_VERSION=$(cat inbm/version.txt)
echo $NEW_VERSION >inbm/version.txt

mv inbm/packaging/yocto/meta-intel-ese-manageability/recipes-inb/inb/inb_{$OLD_VERSION,$NEW_VERSION}.bb
echo ====
echo ==== Remember to update inbm/Changelog.md.
echo ====