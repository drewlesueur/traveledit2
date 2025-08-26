#!/bin/bash

# This script is something I use to stop ssh tunnels
# when seems they are in weird state.
# Fill in $PART_OF_USERNAME appropriately.

ps aux | grep drew.les | grep sshd | awk '{print $2}' | xargs kill
