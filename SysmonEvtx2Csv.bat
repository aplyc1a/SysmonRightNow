@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

:: 检查LogParser是否存在
if not exist "..\LogParser2.2\LogParser.exe" (
    echo 错误：未找到LogParser！请确认路径"..\LogParser2.2\LogParser.exe"是否正确。
    pause
    exit /b 1
)

echo ==============================================
echo 开始导出当前目录下的所有evtx文件到CSV...
echo ==============================================

:: 遍历当前目录下所有.evtx文件
for %%f in (*.evtx) do (
    set "evtx_file=%%f"
    set "csv_file=%%~nf.csv"

    echo.
    echo 正在处理：!evtx_file!
    echo 目标CSV：!csv_file!

    :: 执行LogParser命令（通过into子句指定输出文件）
    :: ..\LogParser2.2\LogParser.exe -i:evt -o:csv -q:ON "select EventLog,RecordNumber,TimeGenerated,TimeWritten,EventID,EventType,EventTypeName,EventCategory,SourceName,ComputerName,SID,Strings, EXTRACT_TOKEN(Strings,0,'|') as Strings0, EXTRACT_TOKEN(Strings,1,'|') as Strings1, EXTRACT_TOKEN(Strings,2,'|') as Strings2, EXTRACT_TOKEN(Strings,3,'|') as Strings3, EXTRACT_TOKEN(Strings,4,'|') as Strings4, EXTRACT_TOKEN(Strings,5,'|') as Strings5, EXTRACT_TOKEN(Strings,6,'|') as Strings6, EXTRACT_TOKEN(Strings,7,'|') as Strings7, EXTRACT_TOKEN(Strings,8,'|') as Strings8, EXTRACT_TOKEN(Strings,9,'|') as Strings9, EXTRACT_TOKEN(Strings,10,'|') as Strings10, EXTRACT_TOKEN(Strings,11,'|') as Strings11, EXTRACT_TOKEN(Strings,12,'|') as Strings12, EXTRACT_TOKEN(Strings,13,'|') as Strings13, EXTRACT_TOKEN(Strings,14,'|') as Strings14, EXTRACT_TOKEN(Strings,15,'|') as Strings15, EXTRACT_TOKEN(Strings,16,'|') as Strings16, EXTRACT_TOKEN(Strings,17,'|') as Strings17, EXTRACT_TOKEN(Strings,18,'|') as Strings18, EXTRACT_TOKEN(Strings,19,'|') as Strings19, EXTRACT_TOKEN(Strings,20,'|') as Strings20, EXTRACT_TOKEN(Strings,21,'|') as Strings21, EXTRACT_TOKEN(Strings,22,'|') as Strings22, EXTRACT_TOKEN(Strings,23,'|') as Strings23, EXTRACT_TOKEN(Strings,24,'|') as Strings24, EXTRACT_TOKEN(Strings,25,'|') as Strings25, EXTRACT_TOKEN(Strings,26,'|') as Strings26, EXTRACT_TOKEN(Strings,27,'|') as Strings27, EXTRACT_TOKEN(Strings,28,'|') as Strings28, EXTRACT_TOKEN(Strings,29,'|') as Strings29, EXTRACT_TOKEN(Strings,30,'|') as Strings30 into '!csv_file!' from '!evtx_file!'"
	
	..\LogParser2.2\LogParser.exe -i:evt -o:csv -q:ON "select EventLog,RecordNumber,TimeGenerated,TimeWritten,EventID,EventType,EventTypeName,EventCategory,SourceName,ComputerName,SID,Strings into '!csv_file!' from '!evtx_file!'"


    :: 检查命令执行结果
    if !errorlevel! equ 0 (
        echo [成功] !evtx_file! 已导出到 !csv_file!
    ) else (
        echo [失败] !evtx_file! 导出失败（可能被占用或格式错误）
    )
)

echo.
echo ==============================================
echo 所有文件处理完毕！
echo ==============================================
pause