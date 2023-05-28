@echo off
title Jusalien GUID Spoofer
reg add "HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" /v HwProfileGuid /t REG_SZ /d "{%random:~-8%-%random:~-4%-%random:~-4%-%random:~-4%-%random:~-12%}" /f
echo HwProfileGuid changed to:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" /v HwProfileGuid

