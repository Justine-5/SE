@echo off
set VENV_DIR=env

:: Step 1: Check if venv exists
if not exist %VENV_DIR%\ (
    echo Creating virtual environment...
    python -m venv %VENV_DIR%
)

:: Step 2: Activate the virtual environment
call %VENV_DIR%\Scripts\activate

:: Step 3: Install requirements if requirements.txt exists
if exist requirements.txt (
    echo Installing dependencies...
    pip install -r requirements.txt
)

:: Step 4: Run the Flask app
start "" cmd /c "timeout /t 5 >nul && start http://127.0.0.1:5000"
flask run
pause