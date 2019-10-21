@echo off
set file=spe32_test
c:\masm32\bin\ml.exe /c /coff /Cp %file%.asm
c:\masm32\bin\link.exe /OPT:NOWIN98 /SECTION:.text,RWE /SUBSYSTEM:WINDOWS,4.0 %file%.obj
del *.obj
:End
pause
cls