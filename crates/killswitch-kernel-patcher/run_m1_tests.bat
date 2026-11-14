@echo off
cargo test -p killswitch-kernel-patcher --test cpe_tests
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
cargo test -p killswitch-kernel-patcher --test discovery_tests
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
cargo test -p killswitch-kernel-patcher --test privilege_tests
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
cargo test -p killswitch-kernel-patcher
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
cargo clippy -p killswitch-kernel-patcher --all-targets -- -D warnings
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
