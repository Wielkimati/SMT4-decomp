@echo off
setlocal
python "%~dp0tools\ghidra_reference.py" --open
if errorlevel 1 (
    echo.
    echo Ghidra could not be launched. See the error above.
    pause
    exit /b 1
)
