@echo off

REM Checks for Javac, if not found, displays error message and exits script
where javac >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: 'javac' not found. Please install the Java JDK and add it to your PATH.
    pause
    exit /b 1
)

REM Check for Streamlit, if not found, displays error message and exits script
where streamlit >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: 'streamlit' not found. Please run 'pip install streamlit'.
    pause
    exit /b 1
)

REM Makes bin/ if not found, compiling Java files in src/ to bin/

if not exist bin mkdir bin 
javac -d bin src/*.java

REM  Starting Streamlit app...
streamlit run app.py
pause