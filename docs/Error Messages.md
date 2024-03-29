# Error Messages

| Error Message                     | Description                                                                                                           | Result                                                                   |
|:----------------------------------|:----------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------|
| COMMAND_SUCCESS                   | Post and pre-install check go through.                                                                                | {'status': 200, 'message': 'COMMAND SUCCESS'}                            |
| FILE_NOT_FOUND                    | File to be fetched is not found.                                                                                      | {'status': 404, 'message': 'FILE NOT FOUND'}                             |
| IMAGE_IMPORT_FAILURE              | Image is already present when Image Import is triggered.                                                              | {'status': 401, 'message': 'FAILED IMAGE IMPORT, IMAGE ALREADY PRESENT'} |
| INSTALL_FAILURE                   | Installation was not successful due to invalid package or one of the source file, signature or version checks failed. | {'status': 400, 'message': 'Error during install: Pre OTA check failed'} |
| OTA_FAILURE                       | Another OTA is in progress when OTA is triggered.                                                                     | {'status': 302, 'message': 'OTA IN PROGRESS, TRY LATER'}                 | 
| SOTA_COMMAND_FAILURE              | SOTA command was not successful.                                                                                      | {'status': 400, 'message': "SOTA command status: FAILURE."}              |
| UNABLE_TO_DOWNLOAD_DOCKER_COMPOSE | Docker-compose download command failed.                                                                               | {'status': 300, 'message': 'FAILED TO PARSE/VALIDATE MANIFEST'}          |
| XML_FAILURE                       | Result of bad formatting, missing mandatory tag.                                                                      | {'status': 300, 'message': 'FAILED TO PARSE/VALIDATE MANIFEST'}          |
