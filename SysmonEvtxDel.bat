@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: 检查管理员权限
fltmc >nul 2>&1 || (goto :needAdmin)

:: 定义目标日志路径（%%转义%，延迟扩展下用!引用变量）
set "targetLog=C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx"

echo 准备删除 Sysmon 日志文件...
echo 目标文件：!targetLog!
echo.

:: 检查文件是否存在（用延迟扩展+双引号强制正确解析路径）
if not exist "!targetLog!" (
    echo 错误：目标文件不存在!
    echo 路径：!targetLog!
    endlocal  
    pause
    exit /b 1
)

:: 通过PowerShell删除（用单引号包裹路径，避免%被PowerShell解析）
PowerShell -Command "Remove-Item -Path '!targetLog!' -Force -ErrorAction Stop" >nul 2>&1

:: 检查删除结果
if %errorlevel% equ 0 (
    echo 日志删除成功!
    echo 已删除文件：!targetLog!
) else (
    echo 错误：日志删除失败！可能原因：
    echo 1. 文件被系统进程锁定（如事件查看器、Sysmon服务，需先关闭）
    echo 2. 权限不足（确认以管理员身份运行）
    echo 3. 路径解析错误（特殊字符导致）
)

    echo 12345
endlocal
pause
exit /b

:needAdmin
echo 操作需要管理员权限，正在请求...
PowerShell -Command "Start-Process -FilePath '%0' -Verb RunAs" >nul 2>&1
exit /b