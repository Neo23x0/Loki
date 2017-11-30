@ECHO OFF
C:\Python27\Scripts\pyinstaller.exe  --icon "%cd%\loki.ico" -F "%cd%\loki-upgrader.py" 
C:\Python27\python.exe loki-package-builder.py --ruledir "%cd%\signatures" --target rules
if exist "%cd%\rules" (
    REM found private rules
    C:\Python27\Scripts\pyinstaller.exe "%cd%\loki-privrules.spec"
) else (
    REM no private rules in builddir
    C:\Python27\Scripts\pyinstaller.exe "%cd%\loki-noprivrules.spec"
)
del /f "%cd%\rules"
del /f "%cd%\rules.key"

