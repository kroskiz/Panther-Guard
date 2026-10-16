#!/bin/bash

# Checks if Javac is available, if not displays an error message and exits the script
if ! command -v javac &> /dev/null; then
    echo "Error: 'javac' could not be found. Please install the Java JDK and add it to your system PATH."
    exit 1
fi

# Checks if Streamlit is available, if not displays an error message and exits the script
if ! command -v streamlit &> /dev/null; then
    echo "Error: 'streamlit' could not be found. Please ensure Streamlit is installed. (You can install it via: pip install streamlit)"
    exit 1
fi

# Creates the bin/ directory if it doesn't exist
mkdir -p bin

# Compiles all Java files inside src/ and outputs the compiled classes to bin/
javac -d bin src/*.java
if [ $? -ne 0 ]; then
    echo "Compilation failed! Check Java syntax."
    exit 1
fi

streamlit run app.py