#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. "$DIR"/../../integration-common/util/tc-messages.sh

suite_started docker-compose
cleanup() {
    suite_finished docker-compose
}
trap cleanup 0
"$DIR"/vagrant-up.sh

test_ignored "docker-compose up" "flaky test"
test_ignored "docker-compose down" "flaky test"

#test_with_command "docker-compose up" \
    #vagrant ssh -c \"sudo /test/docker-compose/TC08_DOCKER_COMPOSE_UP.sh\"
#test_with_command "docker-compose down" \
    #vagrant ssh -c \"sudo /test/docker-compose/TC09_DOCKER_COMPOSE_DOWN.sh\"

test_with_command "docker-compose remove" \
    vagrant ssh -c \"sudo /test/docker-compose/TC_DOCKER_COMPOSE_REMOVE.sh\"

test_with_command "docker-compose pull" \
    vagrant ssh -c \"sudo /test/docker-compose/TC_DOCKER_COMPOSE_PULL.sh\"

test_with_command "docker-compose up with password" \
    vagrant ssh -c \"sudo /test/docker-compose/TC_DOCKER_COMPOSE_PASSWORD.sh\"

suite_finished docker-compose

"$DIR"/vagrant-reboot.sh
