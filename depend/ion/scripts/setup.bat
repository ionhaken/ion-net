@echo off
cd ..

pushd %CD%

call "%~dp0%bin\env.bat"

cd  %~dp0

if not exist "generated" (
	mkdir "generated"
)

if not exist "generated/src" (
	mkdir "generated/src"
)

if not exist "generated/src/ComponentTest" (
	mkdir "generated/src/ComponentTest"
)

%COMPILER% "src\ion_test\model.json" "generated/src/ComponentTest"

%SHARPMAKE% "/sources(@"Core.win32.sharpmake.cs") /verbose"
@if %errorlevel% neq 0 goto :error

%SHARPMAKE% "/sources(@"Core.win64.sharpmake.cs") /verbose"
@if %errorlevel% neq 0 goto :error

%SHARPMAKE% "/sources(@"Core.android.sharpmake.cs") /verbose"
@if %errorlevel% neq 0 goto :error

%SHARPMAKE% "/sources(@"Core.linux.sharpmake.cs") /verbose"
@if %errorlevel% neq 0 goto :error

%SHARPMAKE% "/sources(@"Codegen.sharpmake.cs") /verbose"
@if %errorlevel% neq 0 goto :error

@goto :exit
:error
@echo "========================= ERROR ========================="
@pause

:exit

@echo "OK"
cd %CD%