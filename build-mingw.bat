@echo off

rmdir /s /q build
call :my_sleep

meson setup build --buildtype=release --default-library=static
call :my_sleep

ninja -C build
call :my_sleep

strip build\meson-out\mcupg_server.exe -o .\McupgServerUI.exe
call :my_sleep

upx -9 McupgServerUI.exe

pause

goto :eof

:my_sleep
echo "wait 1s ..."
ping 127.0.0.1 -n 2 > nul
goto :eof
