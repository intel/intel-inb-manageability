#!/bin/bash

# Activate venv
echo Attempting to activate venv. Will fail if ~/venv-3.12 is not set up.
. ~/venv-3.12/bin/activate

# Infinite loop to keep running the tests
while true; do
    # Find all *.py files except __init__.py, shuffle the list, and then read them one by one
    find . -type f -name "*.py" ! -name "__init__.py" -print0 | shuf -z | while IFS= read -r -d '' file; do
        echo "Running Atheris on $file..."
        
        # Log the output to a file named after the Python file but with .log extension
	# Run atheris.
        logfile="$(basename "$file" .py).log"
        PYTHONPATH=../.. timeout --foreground 600 python3 "$file" -- -max_total_time=60 &>> "$logfile"
        
        # Check if the process was killed by timeout to differentiate it from normal completion
        if [ $? -eq 124 ]; then
            echo "Atheris on $file was terminated due to the timeout."
        else
            echo "Atheris on $file completed."
        fi
    done
done
