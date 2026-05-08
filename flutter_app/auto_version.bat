@echo off
setlocal enabledelayedexpansion

set PUBSPEC_FILE=pubspec.yaml

if not exist %PUBSPEC_FILE% (
    echo [ERROR] pubspec.yaml not found in current directory!
    exit /b 1
)

echo Updating version in pubspec.yaml...

set TEMP_FILE=pubspec.yaml.tmp

(for /f "delims=" %%i in (%PUBSPEC_FILE%) do (
    set "line=%%i"
    if "!line:~0,8!"=="version:" (
        for /f "tokens=2 delims=: " %%a in ("!line!") do (
            set "version_str=%%a"
            for /f "tokens=1,2 delims=+" %%b in ("!version_str!") do (
                set "main_v=%%b"
                set "build_v=%%c"
                set /a "new_build_v=!build_v! + 1"
                echo version: !main_v!+!new_build_v!
                echo [SUCCESS] Version updated from !version_str! to !main_v!+!new_build_v!
            )
        )
    ) else (
        echo !line!
    )
)) > %TEMP_FILE%

move /y %TEMP_FILE% %PUBSPEC_FILE% >nul
echo Done.
