@ECHO OFF
:: Build script by A. Fischer and F. Roth
:: November 2017

setlocal enabledelayedexpansion

if exist "C:\Python27-x64\" (
    SET PY=C:\Python27-x64\python.exe
    SET PYI=C:\Python27-x64\Scripts\pyinstaller.exe 
) else (
    SET PY=C:\Python27\python.exe
    SET PYI=C:\Python27\Scripts\pyinstaller.exe
    if not exist "%PY%" goto ERROR
    if not exist "%PYI%" goto ERROR
)

:: Cleaning all old versions
RMDIR /S /Q build

ECHO -----------------------------------------
ECHO LOKI Build Script
ECHO -----------------------------------------
ECHO Checking prerequisites and configuration ...

:: Windows 2003 Support
::
ECHO Checking for msvcr100.dll in order to provide Windows 2003 support ...
SET WIN2003=
if not exist "%SystemRoot%\System32\msvcr100.dll" (
    echo File %SystemRoot%\System32\msvcr100.dll not found.
    echo No support for Windows 2003 server systems.
    echo Download and install https://www.microsoft.com/en-us/download/details.aspx?id=26999 if you need that support
) else (
    echo Required file msvcr100.dll found. Windows 2003 will be supported.
    SET WIN2003=-win2003sup
)

:: Private Rules
:: See https://github.com/Neo23x0/Loki/#package-loki-with-a-custom-ruleset for details
SET PRIVRULES=no
%PY% loki-package-builder.py --ruledir "%cd%\private-signatures" --target rules
if !errorlevel! neq 0 GOTO ERROR
if exist "%cd%\rules" (
    echo Private signatures directory found. The contents will be encrypted and added to the package.
    SET PRIVRULES=
)

:: COMPILATION
:: LOKI Upgrader
ECHO Compiling LOKI UPGRADER ...
%PYI% "%cd%\loki-upgrader%WIN2003%.spec"
if !errorlevel! neq 0 GOTO ERROR
:: LOKI
ECHO Compiling LOKI ...
%PYI% "%cd%\loki-%PRIVRULES%privrules%WIN2003%.spec"
if !errorlevel! neq 0 GOTO ERROR
ECHO Check the ./dist directory for the compiled executables
GOTO END

:ERROR
echo "An error occured. The build failed."

:END
:: CLEANUP
ECHO Cleaning up ...
del /f "%cd%\rules"
del /f "%cd%\rules.key"

