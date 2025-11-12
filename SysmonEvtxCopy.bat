@echo off
chcp 65001

:: 检查是否以管理员权限运行（系统日志可能需要管理员权限访问）
fltmc >nul 2>&1 || (goto :needAdmin)

:: 获取主机名（系统环境变量直接获取）
set "hostname=%COMPUTERNAME%"

:: 通过wmic获取标准格式的日期时间（避免区域设置导致的格式问题）
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value') do set "dt=%%a"
set "timestamp=%dt:~0,4%-%dt:~4,2%-%dt:~6,2%_%dt:~8,2%-%dt:~10,2%-%dt:~12,2%"  :: 格式：YYYY-MM-DD_HH-MM-SS

:: 源文件路径（注意%需要用%%转义）
set "source=C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx"

:: 目标文件路径（当前目录 + 自定义名称）
set "dest=%~dp0Sysmon-%hostname%-%timestamp%.evtx"

:: 执行拷贝
echo 正在拷贝 Sysmon 日志...
echo 源文件：%source%
echo 目标文件：%dest%
echo.

copy "%source%" "%dest%" /Y >nul 2>&1

:: 检查拷贝结果
if %errorlevel% equ 0 (
    echo 日志拷贝成功！文件已保存至：
    echo %dest%
) else (
    echo 错误：日志拷贝失败！可能原因：
    echo 1. 源文件不存在（未安装 Sysmon 或日志未生成）
    echo 2. 权限不足（请确保以管理员身份运行）
)

pause
exit /b

:needAdmin
:: 无管理员权限时，通过PowerShell请求提升
echo 操作需要管理员权限，正在请求...
PowerShell -Command "Start-Process -FilePath '%0' -Verb RunAs" >nul 2>&1
exit /b