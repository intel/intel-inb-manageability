"""
    Cleans up repositories and images

    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
import shutil

from dispatcher.packagemanager.local_repo import DirectoryRepo

from inbm_lib.trtl import Trtl

from .aota_error import AotaError
from .constants import DOCKER_COMPOSE_CACHE

logger = logging.getLogger(__name__)


def cleanup_repo(repo: DirectoryRepo, resource: str) -> None:
    """Cleans up repo object

    @param repo: Repository to remove
    @param resource: resource
    """
    logger.debug("Cleaning up repo  : {}".format(str(repo.get_repo_path())))
    repo.delete(resource)


def remove_directory(repo: DirectoryRepo) -> None:  # pragma: no cover
    """Removes repository

    @param repo: Repository to remove
    """
    try:
        os.rmdir(repo.get_repo_path())
    except (OSError, FileNotFoundError) as e:
        logger.debug(f"Unable to remove repository: {e}")
        raise AotaError('Unable to remove directory')


def cleanup_docker_compose_instance(instance_name: str) -> None:
    """Deletes a specific docker compose package (if it exists)

    @param instance_name name of docker compose package to delete"""

    if instance_name:
        repo = DirectoryRepo(os.path.join(DOCKER_COMPOSE_CACHE, str(instance_name)))
        if repo.exists():
            logger.debug(f"Removing directory : {repo.get_repo_path()}")
            try:
                shutil.rmtree(repo.get_repo_path())   # pragma: no cover
            except OSError as e:
                raise AotaError('Error cleaning docker-compose repo') from e
    else:
        raise AotaError('No instance name provided to cleanup_docker_compose_instance')


def remove_old_images(trtl: Trtl, container_tag: str) -> None:
    """Removes old images

    @param trtl: TRTL instance
    @param container_tag: container tag
    """
    error = trtl.remove_old_images(container_tag.split(':')[0])
    if error is not None:
        raise AotaError("Error: " + str(error) + " while removing old images")
