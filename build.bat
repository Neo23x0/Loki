@ECHO OFF
REM Building LOKI

setlocal enabledelayedexpansion

SET PACKAGE=%CD%\loki
SET DIST=%CD%\dist
SET PYI=pyinstaller

:: Cleaning all old versions
RMDIR /S /Q build

:: BUILD LOKI
ECHO Compiling LOKI ...
%PYI% loki.spec
if !errorlevel! neq 0 GOTO ERROR
ECHO Compiling LOKI UPGRADER ...
%PYI% loki-upgrader.spec
if !errorlevel! neq 0 GOTO ERROR

:: Copy Executables and other files to the package folder
move .\dist\loki.exe %PACKAGE%\
move .\dist\loki-upgrader.exe %PACKAGE%\
mkdir %PACKAGE%\tools
copy .\tools\pe-sieve32.exe %PACKAGE%\tools
copy .\tools\pe-sieve64.exe %PACKAGE%\tools

:: Delete files
REM DEL /Q %PACKAGE%\signature-base
DEL /Q %PACKAGE%\*.log
DEL /Q %DIST%\loki_%VER%.zip
IF EXIST %PACKAGE%\signature-base (
    rmdir %PACKAGE%\signature-base /s /q
)

:ERROR
ECHO An error occurred. Build interrupted.

:END

