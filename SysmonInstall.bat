@echo off
chcp 65001
:: 检查是否已获取管理员权限
fltmc >nul 2>&1 || (goto :needAdmin)

:: 已获取管理员权限，执行.\Sysmon.exe -accepteula -i rule.xml
echo 已获取管理员权限，正在运行 .\Sysmon.exe -accepteula -i rule.xml
cd /d "%~dp0"

.\Sysmon.exe -accepteula -i rule.xml

:: 执行完成后暂停，方便查看输出结果
pause
exit /b

:needAdmin
:: 未获取管理员权限，请求提升权限
echo 正在请求管理员权限...
:: 通过PowerShell以管理员身份重新启动当前批处理文件
PowerShell -Command "Start-Process -FilePath '%0' -Verb RunAs" >nul 2>&1
exit /b