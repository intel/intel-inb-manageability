"""
    Invoker stores and queues commands as well as executes them.

    Copyright (C) 2019-2021 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
"""


import logging
from threading import Thread
from time import sleep

from queue import Queue

logger = logging.getLogger(__name__)


class Invoker:
    """Starts the invoker and waiting for command

    @param queue_size: maximum size of the invoker queue to use before rejecting commands.
    """

    def __init__(self, queue_size):
        self.command_queue: Queue = Queue(queue_size)
        self.running = True
        loop_thread = Thread(target=self.run)
        loop_thread.start()

    def add(self, command):
        """Add the command to invoker's queue

        @param command: instance of command object
        """
        logger.debug('Command received.')

        if not self.command_queue.full():
            logger.debug('Command added to queue.')
            self.command_queue.put(command)
        else:
            logger.info('Command Queue Full. Please try again later.')

    def _handle_command(self):
        """Get the command from queue and execute it"""
        command = self.command_queue.get()
        command.execute()

    def run(self):
        """A loop waiting for command and execute it"""
        while self.running:
            if not self.command_queue.empty():
                worker = Thread(target=self._handle_command)
                worker.setDaemon(True)
                worker.start()
            sleep(0.2)

    def stop(self):
        """Stop the invoker"""
        self.running = False
