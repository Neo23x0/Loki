@ECHO OFF
REM Building Thor and creating SFX

setlocal enabledelayedexpansion

SET PACKAGE=%CD%\loki
SET DIST=%CD%\dist
SET ZIPPER="c:\Program Files\7-Zip\7z.exe"

:: Version
set /p VER="Enter Version: "

:: Cleaning all old versions
RMDIR /S /Q build

:: BUILD LOKI
CALL build.bat

:: Pack
%ZIPPER% a -tzip -mm=Deflate -mmt=off -mx5 -mfb=32 -mpass=1 -sccUTF-8 -mem=AES256 -w%PACKAGE% %DIST%\loki_%VER%.zip %PACKAGE%
GOTO END

:ERROR
ECHO An error occurred. Build interrupted.

:END



