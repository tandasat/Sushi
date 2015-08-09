@echo off
del *.sdf
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q SushiTest\x64  
rmdir /s /q Sushi\x64  
rmdir /s /q ChangeMSR\x64  
del /s *.aps
pause
