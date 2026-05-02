@echo off

where cl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo Visual Studio not found
        pause
        exit /b 1
    )
)

cl.exe /D_USRDLL /D_WINDLL dllmain.cpp /MT /link /DLL /OUT:TestDLL.dll user32.lib

if %ERRORLEVEL% EQU 0 (
    echo Build successful: TestDLL.dll
    del *.obj *.exp *.lib 2>nul
) else (
    echo Build failed
)

pause
