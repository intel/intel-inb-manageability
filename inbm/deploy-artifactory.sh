#!/bin/bash

set -euxo pipefail

# Call this script with: ARTIFACTORY_API_KEY=key ARTIFACTORY_REPO=https://repo.example.com/artifactory/repo-name ./deploy-artifactory.sh
# Script will upload all .debs in working directory to repo as Debian packages

deploy_package () {
    DEBFILE=$1

    set +x
    curl -H "X-JFrog-Art-Api:$ARTIFACTORY_API_KEY" -XPUT "$ARTIFACTORY_REPO/ubuntu/pool/$DEBFILE"';deb.distribution='"$DISTRIBUTION"';deb.component='"$COMPONENT"';deb.architecture='"$ARCHITECTURE" -T "$DEBFILE"
    set -x
}

DISTRIBUTION=impish
COMPONENT=universe
ARCHITECTURE=amd64

# Deploy all .debs in working directory
for i in *.deb ; do
  deploy_package "$i" 
done
