import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import xml.etree.ElementTree as ET
from xml.dom import minidom
import re

class SysmonRuleGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Sysmon 规则文件生成器")
        self.root.geometry("1200x800")
        
        # 设置中文字体
        self.style = ttk.Style()
        self.style.configure(".", font=("SimHei", 10))
        
        # 存储规则组的变量
        self.rule_groups = {}
        self.rule_templates = self._load_sorted_rule_templates()
        self.current_edit_mode = "all"  # 记录当前编辑的是完整配置还是单个模块
        
        # 创建界面
        self._create_widgets()
        
        # 初始预览
        self.update_preview()
    
    def _load_sorted_rule_templates(self):
        """按ID排序的规则模板"""
        return {
            "ProcessCreateExcludes": {
                "id": 1,
                "name": "1) -进程创建（记录进程路径、命令行、父进程等关键信息）",
                "content": r"""<RuleGroup name="ProcessCreateExcludes" groupRelation="or">
            <ProcessCreate onmatch="exclude">
                <Image condition="contains">C:\Windows\System32\svchost.exe</Image>
                <Image condition="contains">C:\Windows\System32\CompPkgSrv.exe</Image>
                <Image condition="contains">C:\Windows\System32\taskhostw.exe</Image>
                <Image condition="contains">C:\WINDOWS\system32\sppsvc.exe</Image>
                <ParentCommandLine condition="contains" >Huorong\Sysdiag\Huorong\AppStore\bin\HrASDaemon.exe</ParentCommandLine>
                <ParentCommandLine condition="contains" >ParentCommandLine: C:\WINDOWS\system32\SearchIndexer.exe /Embedding</ParentCommandLine>
                <ParentCommandLine condition="contains" >C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p</ParentCommandLine>
                <ParentCommandLine condition="contains" >C:\WINDOWS\system32\svchost.exe -k InvSvcGroup -p -s InventorySvc</ParentCommandLine>
                <ParentCommandLine condition="contains" >C:\WINDOWS\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc</ParentCommandLine>
            </ProcessCreate>
        </RuleGroup>"""
            },
            "ProcessCreateIncludes": {
                "id": 1,
                "name": "1) +进程创建（记录进程路径、命令行、父进程等关键信息）",
                "content": r"""<RuleGroup name="ProcessCreateIncludes" groupRelation="or">
            <ProcessCreate onmatch="include">
                <Image condition="contains" /> 
            </ProcessCreate>
        </RuleGroup>"""
            },
            "FileCreateTimeExcludes": {
                "id": 2,
                "name": "2) -文件创建时间被修改（检测文件时间篡改行为）",
                "content": r"""<RuleGroup name="FileCreateTimeExcludes" groupRelation="or">
            <FileCreateTime onmatch="exclude">
            </FileCreateTime>
        </RuleGroup>"""
            },
            "FileCreateTimeIncludes": {
                "id": 2,
                "name": "2) +文件创建时间被修改（检测文件时间篡改行为）",
                "content": r"""<RuleGroup name="FileCreateTimeIncludes" groupRelation="or">
            <FileCreateTime onmatch="include">
                <TargetFilename condition="end with">.exe</TargetFilename>
                <Image condition="begin with">C:\Temp</Image>
                <Image condition="begin with">C:\Windows\Temp</Image>
                <Image condition="begin with">C:\Tmp</Image>
                <Image condition="begin with">C:\Users</Image>
                <Image condition="begin with">\Device\HarddiskVolumeShadowCopy</Image>
            </FileCreateTime>
        </RuleGroup>"""
            },
            "NetworkConnectExcludes": {
                "id": 3,
                "name": "3) -网络连接检测（记录进程发起的 TCP/UDP 连接，含 IP、端口、协议等）",
                "content": r"""<RuleGroup name="NetworkConnectExcludes" groupRelation="or">
            <NetworkConnect onmatch="exclude">
                <DestinationIp condition="contains">127.0.0.</DestinationIp>
                <Image condition="contains">C:\Program Files (x86)\eTrust\SdpServ.exe</Image>
                <Image condition="contains">D:\Program Files (x86)\Qianxin\TrustAgent\trustservice.exe</Image>
                <Image condition="contains">C:\Program Files (x86)\Common Files\Tencent\QQProtect\Bin\QQProtect.exe</Image>
                <Image condition="contains">\AppData\Local\QuarkUpdater\QuarkUpdater\1.0.0.15\updater.exe</Image>
            </NetworkConnect>
        </RuleGroup>"""
            },
            "NetworkConnectIncludes": {
                "id": 3,
                "name": "3) +网络连接检测（记录进程发起的 TCP/UDP 连接，含 IP、端口、协议等）",
                "content": r"""<RuleGroup name="NetworkConnectIncludes" groupRelation="or">
            <NetworkConnect onmatch="include">
                <DestinationIp condition="contains">.</DestinationIp>
            </NetworkConnect>
        </RuleGroup>"""
            },
            "ProcessTerminateExcludes": {
                "id": 5,
                "name": "5) -进程终止（记录终止的进程 ID、路径及操作用户）",
                "content": r"""<RuleGroup name="ProcessTerminateExcludes" groupRelation="or">
            <ProcessTerminate onmatch="exclude">
                <Image condition="contains">C:\Windows\System32\svchost.exe</Image>
            </ProcessTerminate>
        </RuleGroup>"""
            },
            "ProcessTerminateIncludes": {
                "id": 5,
                "name": "5) +进程终止（记录终止的进程 ID、路径及操作用户）",
                "content": r"""<RuleGroup name="ProcessTerminateIncludes" groupRelation="or">
            <ProcessTerminate onmatch="include">
            </ProcessTerminate>
        </RuleGroup>"""
            },
            "DriverLoadExcludes": {
                "id": 6,
                "name": "6) -驱动程序加载（记录驱动路径、数字签名状态、哈希值）",
                "content": r"""<RuleGroup name="DriverLoadExcludes" groupRelation="and">
            <DriverLoad onmatch="exclude">
                <Rule groupRelation="and">
                    <Signature condition="begin with">Intel </Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
                <Rule groupRelation="and">
                    <Signature condition="contains">Microsoft</Signature>
                    <SignatureStatus condition="is">Valid</SignatureStatus>
                </Rule>
            </DriverLoad>
        </RuleGroup>"""
            },
            "DriverLoadIncludes": {
                "id": 6,
                "name": "6) +驱动程序加载（记录驱动路径、数字签名状态、哈希值）",
                "content": r"""<RuleGroup name="DriverLoadIncludes" groupRelation="and">
            <DriverLoad onmatch="include">
                <Rule groupRelation="and">
                    <Signed condition="is">false</Signed>
                    <ImageLoaded condition="contains">.sys</ImageLoaded>
                </Rule>
            </DriverLoad>
        </RuleGroup>"""
            },
            "ImageLoadedExcludes": {
                "id": 7,
                "name": "7) -镜像文件加载（如 DLL 加载，记录加载路径、签名、所属进程）",
                "content": r"""<RuleGroup name="ImageLoadedExcludes" groupRelation="or">
            <ImageLoad onmatch="exclude">
                <ImageLoaded condition="begin with">C:\Windows\System32\</ImageLoaded>
                <ImageLoaded condition="begin with">C:\Windows\SysWOW64\</ImageLoaded>
                <ImageLoaded condition="begin with">C:\Program Files\</ImageLoaded>
            </ImageLoad>
        </RuleGroup>"""
            },
            "ImageLoadedIncludes": {
                "id": 7,
                "name": "7) +镜像文件加载（如 DLL 加载，记录加载路径、签名、所属进程）",
                "content": r"""<RuleGroup name="ImageLoadedIncludes" groupRelation="or">
            <ImageLoad onmatch="include">
                <Signed condition="is">false</Signed>
                <ImageLoaded condition="contains all">mimikatz;cobaltstrike;beacon</ImageLoaded>
                <Image condition="is">C:\Windows\System32\cscript.exe</Image>
                <Image condition="is">powershell.exe</Image>
            </ImageLoad>
        </RuleGroup>"""
            },
            "CreateRemoteThreadExcludes": {
                "id": 8,
                "name": "8) -远程线程创建（检测进程向其他进程注入线程的行为）",
                "content": r"""<RuleGroup name="CreateRemoteThreadExcludes" groupRelation="or">
            <!--Default to log all and exclude a few common processes-->
            <CreateRemoteThread onmatch="exclude">
                <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\wininit.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\csrss.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\services.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\winlogon.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\audiodg.exe</SourceImage>
                <Rule groupRelation="and">
                    <SourceImage condition="is">C:\Windows\System32\dwm.exe</SourceImage>
                    <TargetImage condition="is">C:\Windows\System32\csrss.exe</TargetImage>
                </Rule>
                <TargetImage condition="end with">Google\Chrome\Application\chrome.exe</TargetImage>
                <SourceImage condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</SourceImage>
            </CreateRemoteThread>
        </RuleGroup>"""
            },
            "CreateRemoteThreadIncludes": {
                "id": 8,
                "name": "8) +远程线程创建（检测进程向其他进程注入线程的行为）",
                "content": r"""<RuleGroup name="CreateRemoteThreadIncludes" groupRelation="or">
            <CreateRemoteThread onmatch="include">
            </CreateRemoteThread>
        </RuleGroup>"""
            },
            "RawAccessRead": {
                "id": 9,
                "name": "9) +原始磁盘访问读取（检测进程直接读取磁盘扇区的行为，如病毒窃取数据）",
                "content": r"""<RuleGroup groupRelation="or">
            <RawAccessRead onmatch="include" />
        </RuleGroup>"""
            },
            "ProcessAccessIncludes": {
                "id": 10,
                "name": "10) +进程被访问（记录 A 进程对 B 进程的访问行为，含访问权限、调用栈）",
                "content": r"""<RuleGroup groupRelation="or">
            <ProcessAccess onmatch="include">
                <CallTrace name="Credential Dumping" condition="contains">dbghelp.dll</CallTrace>
                <CallTrace name="Credential Dumping" condition="contains">dbgcore.dll</CallTrace>
                <TargetImage condition="contains">Desktop</TargetImage>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\csrss.exe</TargetImage>
                    <GrantedAccess>0x1F1FFF</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\wininit.exe</TargetImage>
                    <GrantedAccess>0x1F1FFF</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\winlogon.exe</TargetImage>
                    <GrantedAccess>0x1F1FFF</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\services.exe</TargetImage>
                    <GrantedAccess>0x1F1FFF</GrantedAccess>
                </Rule>
                <GrantedAccess name="Process Hollowing">0x21410</GrantedAccess>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
                    <GrantedAccess>0x1FFFFF</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
                    <GrantedAccess>0x1F1FFF</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
                    <GrantedAccess>0x1010</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>
                    <GrantedAccess>0x143A</GrantedAccess>
                </Rule>
                <Rule groupRelation="and">
                    <TargetImage name="Credential Dumping" condition="image">lsass.exe</TargetImage>
                    <SourceImage name="Credential Dumping" condition="image">wsmprovhost.exe</SourceImage>
                </Rule>
                <Rule groupRelation="and" name="Process Injection">
                    <SourceImage condition="contains all">C:\Program Files;\Microsoft Office\Root\Office</SourceImage>
                    <CallTrace condition="contains">\Microsoft Shared\VBA</CallTrace>
                </Rule>
                <Rule groupRelation="and">
                    <CallTrace name="Dynamic-link Library Injection" condition="contains any">UNKNOWN;C:\Users\Public\;C:\Temp\;C:\Windows\Temp\;C:\Windows\SYSTEM32\ntdll.dll;C:\Windows\System32\kernelbase.dll;</CallTrace>
                        <GrantedAccess name="Dynamic-link Library Injection" condition="contains any">
                        0x1F0FFF;<!-- 完全控制权限（包含所有注入所需权限） -->
                        0x0002;<!-- PROCESS_CREATE_THREAD（创建远程线程，注入核心操作） -->
                        0x0020;<!-- PROCESS_VM_WRITE（写入目标进程内存，注入必要步骤） -->
                        0x0008;<!-- PROCESS_VM_OPERATION（内存操作，如分配内存） -->
                        0x0400;<!-- PROCESS_QUERY_INFORMATION（查询目标信息，为注入做准备） -->
                        0x0010<!-- PROCESS_VM_READ（读取内存，结合写入时风险更高） -->
                    </GrantedAccess>
                    <SourceImage condition="is not">C:\WINDOWS\Explorer.EXE</SourceImage>
                    <SourceImage condition="is not">C:\WINDOWS\System32\svchost.exe</SourceImage>
                    <SourceImage condition="is not">C:\WINDOWS\System32\services.exe</SourceImage>
                    <TargetImage condition="end with">.exe</TargetImage>
                </Rule>
                <GrantedAccess name="Process Hollowing">0x0800</GrantedAccess>
                <GrantedAccess name="Credential Dumping">0x0810</GrantedAccess>
                <GrantedAccess name="Process Injection">0x0820</GrantedAccess>
                <GrantedAccess name="Process Hollowing">0x800</GrantedAccess>
                <GrantedAccess name="Credential Dumping">0x810</GrantedAccess>
                <GrantedAccess name="Process Injection">0x820</GrantedAccess>
                <SourceImage name="Masquerading" condition="begin with">C:\PerfLogs\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\$Recycle.bin\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Intel\Logs\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Users\Default\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Users\Public\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Users\NetworkService\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\Fonts\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\Debug\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\Media\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\Help\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\addins\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\repair\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\security\</SourceImage>
                <SourceImage name="Masquerading" condition="begin with">C:\Windows\system32\config\systemprofile\</SourceImage>
                <SourceImage name="Masquerading" condition="contains">VolumeShadowCopy</SourceImage>
                <SourceImage name="Masquerading" condition="contains">\htdocs\</SourceImage>
                <SourceImage name="Masquerading" condition="contains">\wwwroot\</SourceImage>
                <SourceImage name="Masquerading" condition="contains">\Temp\</SourceImage>
                <Rule groupRelation="and">
                    <SourceImage name="Masquerading" condition="contains">\AppData\</SourceImage>
                    <SourceImage condition="not end with">\AppData\Local\Microsoft\Teams\current\Teams.exe</SourceImage>
                </Rule>
                <Rule groupRelation="and">
                    <CallTrace name="PowerShell" condition="contains">System.Management.Automation.ni.dll</CallTrace>
                    <SourceImage condition="is not">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</SourceImage>
                </Rule>
                <Rule groupRelation="and">
                    <CallTrace name="Process Injection" condition="not begin with">C:\Windows\SYSTEM32\ntdll.dll</CallTrace>
                    <CallTrace name="Process Injection" condition="not begin with">C:\Windows\SYSTEM32\win32u.dll</CallTrace>
                    <CallTrace name="Process Injection" condition="not begin with">C:\Windows\SYSTEM32\wow64win.dll</CallTrace>
                </Rule>
            </ProcessAccess>
        </RuleGroup>"""
            },
            "ProcessAccessExcludes": {
                "id": 10,
                "name": "10) -进程被访问（记录 A 进程对 B 进程的访问行为，含访问权限、调用栈）",
                "content": r"""<RuleGroup groupRelation="or">
            <ProcessAccess onmatch="exclude">
                <SourceImage condition="is">C:\Program Files\Adobe\Adobe Creative Cloud Experience\libs\node.exe</SourceImage>
                <SourceImage condition="contains all">C:\Program Files;\Common Files\Adobe\AdobeGCClient\AGMService.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\AcroCEF\AcroCEF.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARMHelper.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files\Adobe\Adobe Photoshop 2021\Photoshop.exe</SourceImage>
                <TargetImage condition="begin with">C:\Program Files\Autodesk\Autodesk Desktop App</TargetImage>
                <TargetImage condition="begin with">C:\Program Files (x86)\Autodesk\Autodesk Desktop App</TargetImage>
                <Rule groupRelation="and">
                    <SourceImage condition="is">C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe</SourceImage>
                    <TargetImage condition="is">C:\Windows\system32\cscript.exe</TargetImage>
                </Rule>
                <SourceImage condition="contains all">C:\WindowsAzure\GuestAgent_;CollectGuestLogs.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files\Microsoft Monitoring Agent\Agent\HealthService.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\CarbonBlack\cb.exe</SourceImage>
                <Rule name="Exclude Chrome SW Reporter into Reporter" groupRelation="and">
                    <SourceImage condition="image">software_reporter_tool.exe</SourceImage>
                    <TargetImage condition="image">software_reporter_tool.exe</TargetImage>
                    <GrantedAccess condition="is">0x1410</GrantedAccess>
                </Rule>
                <Rule name="Exclude Chrome SW Reporter into Chrome" groupRelation="and">
                    <SourceImage condition="image">software_reporter_tool.exe</SourceImage>
                    <TargetImage condition="image">chrome.exe</TargetImage>
                    <GrantedAccess condition="is">0x1410</GrantedAccess>
                </Rule>
                <Rule name="Exclude Chrome SW Reporter Accessing Anything" groupRelation="and">
                    <SourceImage condition="image">software_reporter_tool.exe</SourceImage>
                    <GrantedAccess condition="is">0x1410</GrantedAccess>
                </Rule>
                <SourceImage condition="contains all">C:\Program Files\Elastic\Agent\data\;\metricbeat.exe</SourceImage>
                <SourceImage condition="end with">wmiprvse.exe</SourceImage>
                <SourceImage condition="end with">GoogleUpdate.exe</SourceImage>
                <SourceImage condition="end with">LTSVC.exe</SourceImage>
                <SourceImage condition="end with">taskmgr.exe</SourceImage>
                <SourceImage condition="end with">VBoxService.exe</SourceImage>
                <SourceImage condition="end with">vmtoolsd.exe</SourceImage>
                <SourceImage condition="end with">\Citrix\System32\wfshell.exe</SourceImage>
                <SourceImage condition="is">C:\Windows\System32\lsm.exe</SourceImage>
                <GrantedAccess>0x1000</GrantedAccess>
                <GrantedAccess>0x1400</GrantedAccess>
                <GrantedAccess>0x101400</GrantedAccess>
                <GrantedAccess>0x101000</GrantedAccess>
                <SourceImage condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files\PowerToys\modules\KeyboardManager\KeyboardManagerEngine\PowerToys.KeyboardManagerEngine.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files (x86)\Mobatek\MobaXterm\MobaXterm.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files\Palo Alto Networks\Traps\cyserver.exe</SourceImage>
                <Rule groupRelation="and">
                    <SourceImage condition="contains all">C:\Users\;\AppData\Local\Programs\Microsoft VS Code\Code.exe</SourceImage>
                    <TargetImage condition="contains all">C:\Users\;\AppData\Local\Programs\Microsoft VS Code\Code.exe</TargetImage>
                    <GrantedAccess condition="is">0x1401</GrantedAccess>
                </Rule>
                <SourceImage condition="is">C:\Program Files (x86)\VMware\VMWare Player\vmware-authd.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe</SourceImage>
                <SourceImage condition="is">C:\Program Files\WinZip\FAHWindow64.exe</SourceImage>
            </ProcessAccess>
        </RuleGroup>"""
            },
            "FileCreate": {
                "id": 11,
                "name": "11) +文件创建（记录创建文件的进程、路径、创建时间）",
                "content": r"""<RuleGroup name="FileCreateIncludes" groupRelation="or">
            <FileCreate onmatch="include">
                <TargetFilename name="Application Shimming" condition="contains">C:\Windows\AppPatch\Custom</TargetFilename>
                <TargetFilename condition="end with">.bat</TargetFilename>
                <TargetFilename condition="end with">.cmd</TargetFilename>
                <TargetFilename name="Command and Scripting Interpreter" condition="end with">.chm</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\.azure\accesstokens.json</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\.aws\credentials</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\config\gcloud</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\.alibabacloud\credentials</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\.kube\config</TargetFilename>
                <TargetFilename condition="contains all">C:\Users\;\.ssh\</TargetFilename>
                <Rule groupRelation="and">
                    <Image condition="end with">\WINWORD.EXE</Image>
                    <TargetFilename condition="contains any">.cab;.inf</TargetFilename>
                </Rule>
                <TargetFilename condition="begin with">C:\Users\Default</TargetFilename>
                <TargetFilename condition="contains">Desktop</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="contains">AppData\Local\Microsoft\CLR_v2.0\UsageLogs\</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\cscript.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\wscript.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\wmic.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\mshta.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\svchost.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\regsvr32.exe.log</TargetFilename>
                <TargetFilename name="Office Signed Binary Proxy Execution" condition="end with">\UsageLogs\rundll32.exe.log</TargetFilename>
                <TargetFilename condition="contains">\Downloads\</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\System32\Drivers</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\SysWOW64\Drivers</TargetFilename>
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="contains">Appdata\Local\whatsapp\</TargetFilename>
                    <Image condition="excludes">Appdata\Local\whatsapp\</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="contains">Appdata\Local\Microsoft\Teams\</TargetFilename>
                    <Image condition="excludes">Appdata\Local\Microsoft\Teams\</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="contains">Appdata\Local\slack\</TargetFilename>
                    <Image condition="excludes">Appdata\Local\slack\</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="contains">Appdata\Local\discord\</TargetFilename>
                    <Image condition="excludes">Appdata\Local\discord\</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetFilename condition="end with">.js</TargetFilename>
                    <TargetFilename condition="contains">Appdata\Local\signal\</TargetFilename>
                    <Image condition="excludes">Appdata\Local\signal\</Image>
                </Rule>
                <TargetFilename condition="end with">.exe</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\System32\GroupPolicy\Machine\Scripts</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\System32\GroupPolicy\User\Scripts</TargetFilename>
                <TargetFilename name="Mshta" condition="end with">.hta</TargetFilename>
                <TargetFilename condition="end with">.iso</TargetFilename>
                <TargetFilename condition="end with">.img</TargetFilename>
                <TargetFilename name="JavaScript" condition="end with">.js</TargetFilename>
                <TargetFilename name="JavaScript" condition="end with">.javascript</TargetFilename>
                <TargetFilename condition="end with">.kirbi</TargetFilename>
                <TargetFilename name="Forced Authentication" condition="end with">.lnk</TargetFilename>
                <TargetFilename name="Forced Authentication" condition="end with">.scf</TargetFilename>
                <TargetFilename condition="end with">.application</TargetFilename>
                <TargetFilename condition="end with">.appref-ms</TargetFilename>
                <TargetFilename name="Trusted Developer Utilities Proxy Execution" condition="end with">.*proj</TargetFilename>
                <TargetFilename name="Trusted Developer Utilities Proxy Execution" condition="end with">.sln</TargetFilename>
                <TargetFilename condition="end with">.settingcontent-ms</TargetFilename>
                <TargetFilename condition="end with">.docm</TargetFilename>
                <TargetFilename condition="end with">.pptm</TargetFilename>
                <TargetFilename condition="end with">.xlsm</TargetFilename>
                <TargetFilename condition="end with">.xlm</TargetFilename>
                <TargetFilename condition="end with">.dotm</TargetFilename>
                <TargetFilename condition="end with">.xltm</TargetFilename>
                <TargetFilename condition="end with">.potm</TargetFilename>
                <TargetFilename condition="end with">.ppsm</TargetFilename>
                <TargetFilename condition="end with">.sldm</TargetFilename>
                <TargetFilename condition="end with">.xlam</TargetFilename>
                <TargetFilename condition="end with">.xla</TargetFilename>
                <TargetFilename condition="end with">.iqy</TargetFilename>
                <TargetFilename condition="end with">.slk</TargetFilename>
                <TargetFilename condition="contains">\Content.Outlook\</TargetFilename>
                <TargetFilename condition="contains">Roaming\Microsoft\Outlook\VbaProject.OTM</TargetFilename>
                <TargetFilename condition="end with">.rwz</TargetFilename>
                <TargetFilename condition="contains">Roaming\Microsoft\Outlook\Outlook.xml</TargetFilename>
                <TargetFilename condition="end with">.rft</TargetFilename>
                <TargetFilename condition="end with">.jsp</TargetFilename>
                <TargetFilename condition="end with">.jspx</TargetFilename>
                <TargetFilename condition="end with">.asp</TargetFilename>
                <TargetFilename condition="end with">.aspx</TargetFilename>
                <TargetFilename condition="end with">.php</TargetFilename>
                <TargetFilename condition="end with">.war</TargetFilename>
                <TargetFilename condition="end with">.ace</TargetFilename>
                <TargetFilename name="PowerShell" condition="begin with">C:\Windows\System32\WindowsPowerShell</TargetFilename>
                <TargetFilename name="PowerShell" condition="begin with">C:\Windows\SysWOW64\WindowsPowerShell</TargetFilename>
                <TargetFilename name="PowerShell" condition="end with">.ps1</TargetFilename>
                <TargetFilename name="PowerShell" condition="end with">.ps2</TargetFilename>
                <TargetFilename condition="end with">.py</TargetFilename>
                <TargetFilename condition="end with">.pyc</TargetFilename>
                <TargetFilename condition="end with">.pyw</TargetFilename>
                <TargetFilename condition="end with">.rdp</TargetFilename>
                <Image condition="image">rundll32.exe</Image>
                <TargetFilename condition="begin with">C:\Windows\System32\Tasks</TargetFilename>
                <TargetFilename condition="begin with">C:\Windows\Tasks\</TargetFilename>
                <TargetFilename condition="contains">\Start Menu</TargetFilename>
                <TargetFilename condition="contains">\Startup</TargetFilename>
                <TargetFilename name="Services File Permissions Weakness" condition="begin with">C:\Windows\SysWoW64</TargetFilename>
                <TargetFilename name="Services File Permissions Weakness" condition="begin with">C:\Windows\System32</TargetFilename>
                <TargetFilename name="Services File Permissions Weakness" condition="begin with">C:\Windows\</TargetFilename>
                <TargetFilename condition="end with">.sys</TargetFilename>
                <Rule name="OS Credential Dumping: LSASS Memory" groupRelation="and">
                    <TargetFilename condition="contains">lsass</TargetFilename>
                    <TargetFilename condition="contains any">dmp;DMP</TargetFilename>
                    <Image condition="image">taskmgr.exe</Image>
                </Rule>
                <TargetFilename condition="end with">.url</TargetFilename>
                <TargetFilename condition="end with">.vb</TargetFilename>
                <TargetFilename condition="end with">.vbe</TargetFilename>
                <TargetFilename condition="end with">.vbs</TargetFilename>
                <Rule groupRelation="and">
                    <TargetFilename name="Disable or Modify tools" condition="begin with">C:\Windows\System32\CodeIntegrity\CIPolicies\Active\</TargetFilename>
                    <TargetFilename name="Disable or Modify tools" condition="end with">.cip</TargetFilename>
                </Rule>
                <Rule groupRelation="and">
                    <TargetFilename name="Disable or Modify tools" condition="begin with">C:\Windows\System32\CodeIntegrity\</TargetFilename>
                    <TargetFilename name="Disable or Modify tools" condition="end with">.p7b</TargetFilename>
                </Rule>
                <TargetFilename name="Windows Management Instrumentation" condition="begin with">C:\Windows\System32\Wbem</TargetFilename>
                <TargetFilename name="Windows Management Instrumentation" condition="begin with">C:\Windows\SysWOW64\Wbem</TargetFilename>
                <Image name="Windows Management Instrumentation" condition="begin with">C:\WINDOWS\system32\wbem\scrcons.exe</Image>
                <TargetFilename name="Services File Permissions Weakness" condition="begin with">C:\Windows\Temp\</TargetFilename>
                <TargetFilename name="Services File Permissions Weakness" condition="begin with">C:\Program\</TargetFilename>
                <TargetFilename name="File System Permissions Weakness" condition="begin with">C:\Temp\</TargetFilename>
                <TargetFilename name="File System Permissions Weakness" condition="begin with">C:\PerfLogs\</TargetFilename>
                <TargetFilename name="File System Permissions Weakness" condition="begin with">C:\Users\Public\</TargetFilename>
                <TargetFilename name="File System Permissions Weakness" condition="contains">\AppData\Temp\</TargetFilename>
            </FileCreate>
        </RuleGroup>"""
            },
            "RegistryEventIncludes": {
                "id": 12,
                "name": "12、13、14) +注册表项添加 / 删除（检测注册表关键项的创建或删除操作）",
                "content": r"""<RuleGroup name="RegistryEventIncludes" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject name="Application Shimming" condition="contains">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB</TargetObject>
                <TargetObject name="Application Shimming" condition="contains">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom</TargetObject>
                <TargetObject name="Authentication Package" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication</TargetObject>
                <TargetObject name="Authentication Package" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL</TargetObject>
                <TargetObject name="Authentication Package" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NtlmMinClientSec</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">\CurrentVersion\Run</TargetObject>
                <TargetObject condition="contains">\Group Policy\Scripts</TargetObject>
                <TargetObject name="Boot or Logon Initialization Scripts" condition="contains">\Windows\System\Scripts</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">\Policies\Explorer\Run</TargetObject>
                <TargetObject condition="end with">\ServiceDll</TargetObject>
                <TargetObject condition="end with">\ImagePath</TargetObject>
                <TargetObject condition="end with">\Start</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Specialaccounts\userlist</TargetObject>
                <TargetObject name="Winlogon Helper DLL" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Uihostl</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains all">HKLM\SYSTEM\;Control\Session Manager\BootExecute</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains all">HKLM\SYSTEM\;Control\Session Manager\excludefromknowndlls</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains all">HKLM\SYSTEM\;Control\Session Manager\safedllsearchmode</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains all">HKLM\SYSTEM\;Control\Session Manager\setupexecute</TargetObject>
                <TargetObject name="Change Default File Association" condition="contains">\Explorer\FileExts</TargetObject>
                <TargetObject condition="contains">\shell\install\command</TargetObject>
                <TargetObject condition="contains">\shell\open\command</TargetObject>
                <TargetObject condition="contains">\shell\open\ddeexec</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains all">software\microsoft\windows nt\currentversion\accessibility\ATs\;\StartExe</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">software\microsoft\windows nt\currentversion\windows\run\</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">software\microsoft\windows\currentversion\explorer\shell folders\common startup</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="contains">software\microsoft\windows\currentversion\explorer\shell folders\startup</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="begin with">hklm\software\microsoft\command processor\autorun</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="contains">\mscfile\shell\open\command</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="contains">ms-settings\shell\open\command</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="contains">Classes\exefile\shell\runas\command\isolatedCommand</TargetObject>
                <TargetObject name="Component Object Model Hijacking" condition="contains all">Software\Classes\CLSID;inprocserver32</TargetObject>
                <TargetObject name="Component Object Model Hijacking" condition="contains all">Software\Classes\CLSID;localserver32</TargetObject>
                <TargetObject name="Component Object Model Hijacking" condition="contains all">Classes\CLSID\;TreatAs</TargetObject>
                <TargetObject name="Security Account Manager" condition="contains">System\CurrentControlSet\Services\VSS</TargetObject>
                <TargetObject name="Account Manipulation" condition="contains">\services\Netlogon\Parameters\DisablePasswordChange</TargetObject>
                <TargetObject name="Appinit DLLs" condition="contains all">HKLM\SOFTWARE\;Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls</TargetObject>
                <TargetObject name="Appinit DLLs" condition="contains all">HKLM\SOFTWARE\;Microsoft\Windows NT\CurrentVersion\Windows\loadappinit_dlls</TargetObject>
                <TargetObject name="Appinit DLLs" condition="contains all">\SYSTEM\;\Services\DNS\Parameters\ServerLevelPluginDll</TargetObject>
                <TargetObject name="Impair Defenses - Indicator Blocking" condition="end with">SOFTWARE\Microsoft\.NETFramework\ETWEnabled</TargetObject>
                <TargetObject name="Accessibility Features" condition="contains">\Environment\</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\setup\cmdline</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\setup\upgrade</TargetObject>
                <TargetObject condition="contains all">Software\microsoft\ctf\langbaraddin\;\Enable</TargetObject>
                <TargetObject condition="contains all">Software\microsoft\ctf\langbaraddin\;\FilePath</TargetObject>
                <TargetObject condition="contains">Software\policies\microsoft\windows\control panel\desktop\scrnsave.exe</TargetObject>
                <TargetObject condition="begin with">HKLM\Software\Classes\protocols\filter\</TargetObject>
                <TargetObject condition="begin with">HKLM\Software\Classes\protocols\handler\</TargetObject>
                <TargetObject name="Disable Windows Event Logging" condition="contains all">\SYSTEM\;\Service\EventLog;Retention</TargetObject>
                <TargetObject name="Disable Windows Event Logging" condition="contains all">\SYSTEM\;\Service\EventLog;MaxSize</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions</TargetObject>
                <TargetObject name="Image File Execution Options Injection" condition="begin with">HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</TargetObject>
                <TargetObject name="Image File Execution Options Injection" condition="begin with">HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</TargetObject>
                <TargetObject condition="contains">\Internet Explorer\Toolbar</TargetObject>
                <TargetObject condition="contains">\Internet Explorer\Extensions</TargetObject>
                <TargetObject condition="contains">\Browser Helper Objects</TargetObject>
                <TargetObject condition="contains">\software\microsoft\internet explorer\desktop\components\Source</TargetObject>
                <TargetObject condition="contains">\software\microsoft\internet explorer\explorer bars\</TargetObject>
                <TargetObject condition="contains">\software\microsoft\internet explorer\Styles\MaxScriptStatements</TargetObject>
                <TargetObject condition="contains">\software\microsoft\internet explorer\toolbar\WebBrowser\ITBarLayout</TargetObject>
                <TargetObject condition="contains">\software\wow6432node\microsoft\internet explorer\toolbar\WebBrowser\ITBarLayout</TargetObject>
                <TargetObject condition="contains">\software\microsoft\internet explorer\urlsearchhooks\</TargetObject>
                <TargetObject condition="contains">HKLM\software\wow6432node\microsoft\internet explorer\urlsearchhooks\</TargetObject>
                <TargetObject name="Port Monitors" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors</TargetObject>
                <TargetObject condition="begin with">hklm\system\mounteddevices\</TargetObject>
                <TargetObject condition="contains all">hklm\system\;\enum\usb\</TargetObject>
                <TargetObject name="Netsh Helper DLL" condition="contains">SOFTWARE\Microsoft\Netsh</TargetObject>
                <TargetObject name="Office Add-ins" condition="contains all">\Microsoft\Office;\Outlook\Addins</TargetObject>
                <TargetObject name="Office Add-ins" condition="contains">\Software\Microsoft\VSTO\Security\Inclusion</TargetObject>
                <TargetObject name="Office Add-ins" condition="contains">\Software\Microsoft\VSTO\SolutionMetadata</TargetObject>
                <TargetObject name="Outlook Server 95/98 Identity Keys" condition="contains">Identities</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\Account Name</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\Display Name</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\Email</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\HTTP Password</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\HTTP User</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\IMAP Password</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\IMAP User</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\MAPI Provider</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\POP3 Password</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\POP3 User</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\SMTP Password</TargetObject>
                <TargetObject condition="contains all">SOFTWARE\Microsoft\Office\;\Outlook\Profiles\;\9375CFF0413111d3B88A00104B2A6676\;\SMTP User</TargetObject>
                <TargetObject name="Outlook Home Page" condition="contains all">software\microsoft\office\;\outlook\security\</TargetObject>
                <TargetObject name="Outlook Home Page" condition="contains all">software\microsoft\office\;\outlook\today\</TargetObject>
                <TargetObject name="Outlook Home Page" condition="contains all">software\microsoft\office\;\outlook\webview\;\</TargetObject>
                <TargetObject condition="contains all">software\microsoft\office\;\word\options\globaldotname</TargetObject>
                <TargetObject condition="contains all">software\microsoft\office\;\common\internet\server cache\</TargetObject>
                <TargetObject condition="contains all">software\;microsoft\office\;\addins\</TargetObject>
                <TargetObject condition="contains all">software\;microsoft\office\;\Common\COM Compatibility</TargetObject>
                <TargetObject condition="contains">\Security\Trusted Documents\TrustRecords</TargetObject>
                <TargetObject condition="contains">\Security\Trusted Documents\</TargetObject>
                <TargetObject condition="end with">\UrlUpdateInfo</TargetObject>
                <TargetObject condition="contains">software\microsoft\windows\currentversion\explorer\recentdocs\.docx\</TargetObject>
                <TargetObject condition="contains">software\microsoft\windows\currentversion\explorer\recentdocs\.xlsx\</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Clients\Mail\Microsoft Outlook\DllPath</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Clients\Mail\Microsoft Outlook\DllPathEx</TargetObject>
                <TargetObject condition="contains">software\microsoft\Office test\special\perf\</TargetObject>
                <TargetObject condition="contains all">software\microsoft\office\;\Options\OPEN</TargetObject>
                <TargetObject name="Office Add-ins" condition="contains all">\Microsoft\Office;\PowerPoint\Addins</TargetObject>
                <TargetObject name="office" condition="end with">\Word\Security\AllowDDE</TargetObject>
                <TargetObject name="office" condition="end with">\Excel\Security\DisableDDEServerLaunch</TargetObject>
                <TargetObject name="office" condition="end with">\Excel\Security\DisableDDEServerLookup</TargetObject>
                <TargetObject name="office" condition="end with">\VBAWarnings</TargetObject>
                <TargetObject name="office" condition="end with">\DisableInternetFilesInPV</TargetObject>
                <TargetObject name="office" condition="end with">\DisableUnsafeLocationsInPV</TargetObject>
                <TargetObject name="office" condition="end with">\DisableAttachementsInPV</TargetObject>
                <TargetObject name="Remote Desktop Protocol" condition="is">HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxInstanceCount</TargetObject>
                <TargetObject name="Remote Desktop Protocol" condition="is">HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\RaunSolicit</TargetObject>
                <TargetObject name="Modify Registry" condition="begin with">HKLM\SYSTEM\CurrentControlSet\services\TermService\Parameters\ServiceDll</TargetObject>
                <TargetObject name="Modify Registry" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fSingleSessionPerUser</TargetObject>
                <TargetObject name="Modify Registry" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections</TargetObject>
                <TargetObject name="Modify Registry" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Shadow</TargetObject>
                <TargetObject name="Scheduled Task" condition="contains all">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks;Actions</TargetObject>
                <TargetObject name="Scheduled Task" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</TargetObject>
                <TargetObject name="Scheduled Task" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\</TargetObject>
                <TargetObject name="Security Support Provider" condition="contains">SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
                <TargetObject name="SIP and Trust Provider Hijacking" condition="begin with">HKLM\SOFTWARE\Microsoft\Cryptography\OID</TargetObject>
                <TargetObject name="SIP and Trust Provider Hijacking" condition="begin with">HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID</TargetObject>
                <TargetObject name="SIP and Trust Provider Hijacking" condition="begin with">HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust</TargetObject>
                <TargetObject name="SIP and Trust Provider Hijacking" condition="begin with">HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust</TargetObject>
                <TargetObject name="SIP and Trust Provider Hijacking" condition="begin with">HKLM\SOFTWARE\Microsoft\Cryptography\Offload\ExpoOffload</TargetObject>
                <TargetObject name="Service Execution" condition="end with">\PsExec\EulaAccepted</TargetObject>
                <TargetObject name="Ingress Tool Transfer" condition="end with">\PsFile\EulaAccepted</TargetObject>
                <TargetObject name="System Owner/User Discovery" condition="end with">\PsGetSID\EulaAccepted</TargetObject>
                <TargetObject name="Process Discovery" condition="end with">\PsInfo\EulaAccepted</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="end with">\PsKill\EulaAccepted</TargetObject>
                <TargetObject name="Process Discovery" condition="end with">\PsList\EulaAccepted</TargetObject>
                <TargetObject name="System Owner/User Discovery" condition="end with">\PsLoggedOn\EulaAccepted</TargetObject>
                <TargetObject name="Service Execution" condition="end with">\PsLogList\EulaAccepted</TargetObject>
                <TargetObject name="Account Manipulation" condition="end with">\PsPasswd\EulaAccepted</TargetObject>
                <TargetObject name="Service Execution" condition="end with">\PsService\EulaAccepted</TargetObject>
                <TargetObject name="undefined" condition="end with">\PsShutDown\EulaAccepted</TargetObject>
                <TargetObject name="undefined" condition="end with">\PsSuspend\EulaAccepted</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="contains">SYSTEM\CurrentControlSet\services\SysmonDrv</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="contains">SYSTEM\CurrentControlSet\services\Sysmon</TargetObject>
                <TargetObject name="Registry Run Keys / Start Folder" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram</TargetObject>
                <TargetObject name="Time Providers" condition="contains">HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders</TargetObject>
                <TargetObject name="Signed Binary Proxy Execution" condition="begin with">HKLM\Software\Microsoft\WAB\DLLPath</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Control.exe</TargetObject>
                <TargetObject name="AppCert DLLs" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls</TargetObject>
                <TargetObject name="Component Object Model Hijacking" condition="contains">software\classes\clsid\{083863f1-70de-11d0-bd40-00a0c911ce86}\instance</TargetObject>
                <TargetObject name="Component Object Model Hijacking" condition="contains">software\classes\clsid\{7ed96837-96f0-4812-b211-f13c24117ed3}\instance</TargetObject>
                <Rule groupRelation="and">
                    <TargetObject name="Video Capture" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Audio Capture" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Audio Capture" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Data from Local System" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Data from Local System" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Data from Local System" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Input Capture - Keylogging" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice</TargetObject>
                    <Image condition="excludes any">Google\Chrome\Application\chrome.exe;Zoom\bin\Zoom.exe;slack\slack.exe;Mozilla Firefox\firefox.exe</Image>
                </Rule>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Plap Providers</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa</TargetObject>
                <TargetObject name="Credential Dumping" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\</TargetObject>
                <TargetObject name="Credential Dumping" condition="contains">\Control\SecurityProviders\WDigest</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\AntiVirusDisableNotify</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="contains all">HKLM\software\microsoft\microsoft antimalware\exclusions\</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\software\microsoft\Windows Advanced Threat Protection\TelLib</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\software\policies\microsoft\windows advanced threat protection\</TargetObject>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\Sense</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\WinDefend</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\MsMpSvc</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\NisSrv</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\WdBoot</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\wscsvc</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\wuauserv</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc</TargetObject>
                    <Details condition="contains">DWORD (0x00000004)</Details>
                </Rule>
                <TargetObject condition="begin with">hklm\software\microsoft\windows script\settings\amsienable</TargetObject>
                <TargetObject condition="contains">\software\microsoft\windows script\settings\amsienable</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\FirewallDisableNotify</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\FirewallOverride</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\software\policies\microsoft\windowsfirewall\;\authorizedapplications</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\software\policies\microsoft\windowsfirewall\;\authorizedapplications\list</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\software\policies\microsoft\windowsfirewall\;\globallyopenports</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Safeboot</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\Winlogon</TargetObject>
                <TargetObject condition="end with">\FriendlyName</TargetObject>
                <TargetObject condition="is">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress\(Default)</TargetObject>
                <Rule groupRelation="and">
                    <TargetObject name="Bypass User Access Control" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System</TargetObject>
                    <Image condition="is not">C:\Windows\System32\svchost.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject name="Bypass User Access Control" condition="contains">\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System</TargetObject>
                    <Image condition="is not">C:\Windows\System32\svchost.exe</Image>
                </Rule>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles</TargetObject>
                <TargetObject name="Boot or Logon Autostart Execution - Port Monitors" condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports</TargetObject>
                <TargetObject name="Boot or Logon Autostart Execution - Port Monitors" condition="contains">\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="contains all">software\microsoft\powershell\;\shellids\microsoft.powershell\executionpolicy</TargetObject>
                <TargetObject name="Install Root Certificate" condition="begin with">HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates</TargetObject>
                <TargetObject name="Install Root Certificate" condition="contains">\Microsoft\SystemCertificates\Root\Certificates</TargetObject>
                <TargetObject name="Install Root Certificate" condition="contains">\Microsoft\SystemCertificates\CA\Certificates</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\AllAlertsDisabled</TargetObject>
                <TargetObject name="Disable or Modify Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\DisableMonitoring</TargetObject>
                <TargetObject condition="contains">\Classes\AllFilesystemObjects</TargetObject>
                <TargetObject condition="contains">\Classes\Directory</TargetObject>
                <TargetObject condition="contains">\Classes\Drive</TargetObject>
                <TargetObject condition="contains">\Classes\Folder</TargetObject>
                <TargetObject condition="contains">\ShellEx\ContextMenuHandlers</TargetObject>
                <TargetObject condition="contains">\CurrentVersion\Shell</TargetObject>
                <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks</TargetObject>
                <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellServiceObject</TargetObject>
                <TargetObject name="Exploitation of Remote Services" condition="contains all">HKLM\SOFTWARE\Microsoft\Windows;\CurrentVersion\Print\Connections</TargetObject>
                <TargetObject name="Exploitation of Remote Services" condition="contains all">HKLM\System;\control\print\monitors</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="contains">\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command</TargetObject>
                <TargetObject condition="contains">{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy</TargetObject>
                <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUsername</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\UacDisableNotify</TargetObject>
                <TargetObject name="Bypass User Access Control" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\UpdatesDisableNotify</TargetObject>
                <TargetObject name="UACMe Dir Prep" condition="contains all">HKU;Environment</TargetObject>
                <TargetObject name="UACMe Dir Prep" condition="contains all">HKLM;Environment</TargetObject>
                <TargetObject condition="is">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Setup\ServiceStartup</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending\</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting\</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired\</TargetObject>
                <TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services\WinSock</TargetObject>
                <TargetObject condition="end with">\ProxyServer</TargetObject>
                <TargetObject name="Windows Management Instrumentation" condition="contains">SYSTEM\CurrentControlSet\Control\CrashControl</TargetObject>
                <TargetObject name="Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\autologger\senseauditlogger</TargetObject>
                <TargetObject name="Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\autologger\senseeventlog</TargetObject>
                <TargetObject name="Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\EtwMaxLoggers</TargetObject>
                <TargetObject name="Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\Security</TargetObject>
            </RegistryEvent>
        </RuleGroup>
"""
            },
            "RegistryEventExcludes": {
                "id": 12,
                "name": "12、13、14) -注册表项添加 / 删除（检测注册表关键项的创建或删除操作）",
                "content": r"""<RuleGroup name="RegistryEventExcludes" groupRelation="or">
            <RegistryEvent onmatch="exclude">
                <Image condition="is">C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\aciseposture.exe</Image>
                <Image condition="is">C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnagent.exe</Image>
                <Image condition="is">C:\Program Files\Cylance\Optics\CyOptics.exe</Image>
                <Image condition="is">C:\Program Files\Cylance\Desktop\CylanceSvc.exe</Image>
                <Rule groupRelation="and">
                    <Image condition="image">svchost.exe</Image>
                    <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters</TargetObject>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="image">svchost.exe</Image>
                    <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces</TargetObject>
                </Rule>
                <TargetObject condition="end with">Toolbar\WebBrowser</TargetObject>
                <TargetObject condition="end with">Toolbar\WebBrowser\ITBar7Height</TargetObject>
                <TargetObject condition="end with">Toolbar\ShellBrowser\ITBar7Layout</TargetObject>
                <TargetObject condition="end with">Internet Explorer\Toolbar\Locked</TargetObject>
                <TargetObject condition="end with">ShellBrowser</TargetObject>
                <Image condition="is">C:\Program Files (x86)\Ivanti\Workspace Control\pfwsmgr.exe</Image>
                <Image condition="is">C:\Program Files\RES Software\Workspace Manager\pfwsmgr.exe</Image>
                <Image condition="begin with">C:\Program Files (x86)\Kaspersky Lab\Kaspersky Internet Security </Image>
                <Image condition="begin with">C:\Program Files\Kaspersky Lab\Kaspersky Internet Security </Image>
                <Image condition="is">C:\Program Files\McAfee\Endpoint Encryption Agent\MfeEpeHost.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Endpoint Security\Adaptive Threat Protection\mfeatp.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Endpoint Security\Endpoint Security Platform\mfeesp.exe</Image>
                <Image condition="is">C:\Program Files\Common Files\McAfee\Engine\AMCoreUpdater\amupdate.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Agent\masvc.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Agent\x86\mfemactl.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Agent\x86\McScript_InUse.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Agent\x86\macompatsvc.exe</Image>
                <Image condition="is">C:\Program Files\McAfee\Endpoint Security\Threat Prevention\mfeensppl.exe</Image>
                <Image condition="begin with">C:\Program Files\Common Files\McAfee\Engine\scanners</Image>
                <Image condition="is">C:\Program Files\Common Files\McAfee\AVSolution\mcshield.exe</Image>
                <Image condition="is">C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe</Image>
                <Image condition="is">C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.exe</Image>
                <Image condition="is">C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe</Image>
                <Rule groupRelation="and">
                    <Image condition="is">C:\Program Files\Microsoft Monitoring Agent\Agent\HealthService.exe</Image>
                    <TargetObject condition="begin with">HKLM\System\CurrentControlSet\Services\HealthService\Parameters\Management Groups</TargetObject>
                </Rule>
                <TargetObject condition="contains">\{CAFEEFAC-</TargetObject>
                <EventType condition="is">CreateKey</EventType>
                <TargetObject condition="begin with">HKLM\COMPONENTS</TargetObject>
                <Image condition="is">C:\Program Files\ownCloud\owncloud.exe</Image>
                <Image condition="is">C:\Program Files (x86)\ownCloud\owncloud.exe</Image>
                <Rule groupRelation="and">
                    <Image condition="image">svchost.exe</Image>
                    <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks</TargetObject>
                </Rule>
                <Image condition="begin with">C:\Program Files\SentinelOne\Sentinel Agent</Image>
                <Image condition="is">System</Image>
                <Rule groupRelation="and">
                    <Image condition="is">C:\Program Files\VMware\VMware Tools\vmtoolsd.exe</Image>
                    <TargetObject condition="is">HKLM\System\CurrentControlSet\Services\Tcpip\Parameters</TargetObject>
                </Rule>
                <Image condition="is">C:\Program Files (x86)\Webroot\WRSA.exe</Image>
                <Image condition="is">C:\Program Files\WIDCOMM\Bluetooth Software\btwdins.exe</Image>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit</TargetObject>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit\AuditPolicy</TargetObject>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit\PerUserAuditing\System</TargetObject>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SspiCache</TargetObject>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains</TargetObject>
                <TargetObject condition="end with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit</TargetObject>
                <TargetObject condition="contains">\OpenWithProgids</TargetObject>
                <TargetObject condition="end with">\OpenWithList</TargetObject>
                <TargetObject condition="end with">\UserChoice</TargetObject>
                <TargetObject condition="end with">\UserChoice\ProgId</TargetObject>
                <TargetObject condition="end with">\UserChoice\Hash</TargetObject>
                <TargetObject condition="end with">\OpenWithList\MRUList</TargetObject>
                <TargetObject condition="end with">} 0xFFFF</TargetObject>
                <Image condition="end with">Office\root\integration\integrator.exe</Image>
                <Image condition="is">C:\WINDOWS\system32\backgroundTaskHost.exe</Image>
                <Image condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe</Image>
                <Image condition="is">C:\Program Files\Windows Defender\MsMpEng.exe</Image>
                <Image condition="is">C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe</Image>
                <Image condition="is">C:\Program Files\Microsoft Application Virtualization\Client\AppVClient.exe</Image>
                <TargetObject condition="end with">\CurrentVersion\App Paths</TargetObject>
                <TargetObject condition="end with">\CurrentVersion\Image File Execution Options</TargetObject>
                <TargetObject condition="end with">\CurrentVersion\Shell Extensions\Cached</TargetObject>
                <TargetObject condition="end with">\CurrentVersion\Shell Extensions\Approved</TargetObject>
                <TargetObject condition="end with">}\PreviousPolicyAreas</TargetObject>
                <TargetObject condition="contains">\Control\WMI\Autologger\</TargetObject>
                <TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc\Start</TargetObject>
                <TargetObject condition="end with">\Lsa\OfflineJoin\CurrentValue</TargetObject>
                <TargetObject condition="end with">\Components\TrustedInstaller\Events</TargetObject>
                <TargetObject condition="end with">\Components\TrustedInstaller</TargetObject>
                <TargetObject condition="end with">\Components\Wlansvc</TargetObject>
                <TargetObject condition="end with">\Components\Wlansvc\Events</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\</TargetObject>
                <TargetObject condition="end with">\Directory\shellex</TargetObject>
                <TargetObject condition="end with">\Directory\shellex\DragDropHandlers</TargetObject>
                <TargetObject condition="end with">\Drive\shellex</TargetObject>
                <TargetObject condition="end with">\Drive\shellex\DragDropHandlers</TargetObject>
                <TargetObject condition="contains">_Classes\AppX</TargetObject>
                <TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\</TargetObject>
                <TargetObject condition="contains all">SOFTWARE;\Microsoft\EnterpriseCertificates\Disallowed</TargetObject>
                <TargetObject condition="contains all">SOFTWARE;\Microsoft\SystemCertificates\Disallowed</TargetObject>
                <TargetObject condition="contains">Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing</TargetObject>
                <TargetObject condition="is">HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates</TargetObject>
                <Image condition="is">C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe</Image>
                <Image condition="begin with">C:\$WINDOWS.~BT\</Image>
                <TargetObject condition="is">HKLM\System\CurrentControlSet\Services\Tcpip\Parameters</TargetObject>
                <Rule groupRelation="and">
                    <Image condition="is">C:\Windows\system32\lsass.exe</Image>
                    <TargetObject condition="contains">HKLM\System\CurrentControlSet\Services</TargetObject>
                </Rule>
                <Rule groupRelation="and">
                    <TargetObject condition="contains">SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization</TargetObject>
                    <Image condition="is">C:\Windows\System32\svchost.exe</Image>
                </Rule>
                <TargetObject condition="is">HKLM\System\CurrentControlSet\Services\W32Time\Config\LastKnownGoodTime</TargetObject>
                <TargetObject condition="is">HKLM\System\CurrentControlSet\Services\SmsRouter\State\Registration\Ids</TargetObject>
                <TargetObject condition="end with">\services\clr_optimization_v2.0.50727_32\Start</TargetObject>
                <TargetObject condition="end with">\services\clr_optimization_v2.0.50727_64\Start</TargetObject>
                <TargetObject condition="end with">\services\clr_optimization_v4.0.30319_32\Start</TargetObject>
                <TargetObject condition="end with">\services\clr_optimization_v4.0.30319_64\Start</TargetObject>
                <TargetObject condition="end with">\services\DeviceAssociationService\Start</TargetObject>
                <TargetObject condition="end with">\services\BITS\Start</TargetObject>
                <TargetObject condition="end with">\services\TrustedInstaller\Start</TargetObject>
                <TargetObject condition="end with">\services\tunnel\Start</TargetObject>
                <TargetObject condition="end with">\services\UsoSvc\Start</TargetObject>
            </RegistryEvent>
        </RuleGroup>"""
            },
            "RegistryEventIncludes2": {
                "id": 12,
                "name": "12) -注册表项添加 / 删除（检测注册表关键项的创建或删除操作）",
                "content": r"""<RuleGroup name="RegistryEventIncludes2" groupRelation="or">
            <RegistryEvent onmatch="include">
                <TargetObject condition="contains">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
                <TargetObject condition="contains">HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce</TargetObject>
                <TargetObject condition="contains">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</TargetObject>
                <TargetObject condition="contains">HKLM\System\CurrentControlSet\Services</TargetObject>
                <TargetObject condition="contains">HKLM\Software\Microsoft\Windows Defender</TargetObject>
                <TargetObject condition="contains">HKLM\Software\Policies\Microsoft\Windows Defender</TargetObject>
            </RegistryEvent>
        </RuleGroup>"""
            },
            "FileCreateStreamHash": {
                "id": 15,
                "name": "15) +文件流创建（含 NTFS 备用数据流，记录流路径、哈希值，可检测隐藏数据）",
                "content": r"""<RuleGroup name="FileCreateStreamHash" groupRelation="or">
            <FileCreateStreamHash onmatch="include">
                <TargetFilename condition="contains">Temp\7z</TargetFilename>
                <TargetFilename condition="end with">.bat</TargetFilename>
                <TargetFilename condition="end with">.cmd</TargetFilename>
                <TargetFilename condition="end with">Temp\debug.bin</TargetFilename>
                <TargetFilename condition="end with">.dll</TargetFilename>
                <TargetFilename condition="end with">.exe</TargetFilename>
                <TargetFilename condition="end with">.hta</TargetFilename>
                <Rule name="Drive-by Compromise" groupRelation="and">
                    <TargetFilename condition="end with">:Zone.Identifier</TargetFilename>
                    <Contents condition="contains any">blob:;about:internet</Contents>
                </Rule>
                <TargetFilename condition="end with">.lnk</TargetFilename>
                <TargetFilename condition="contains">Content.Outlook</TargetFilename>
                <TargetFilename name="PowerShell" condition="end with">.ps1</TargetFilename>
                <TargetFilename name="PowerShell" condition="end with">.ps2</TargetFilename>
                <TargetFilename condition="end with">.reg</TargetFilename>
                <TargetFilename condition="contains">Downloads</TargetFilename>
                <TargetFilename condition="contains">AppData</TargetFilename>
                <TargetFilename condition="contains">Temp</TargetFilename>
                <TargetFilename condition="contains">ProgramData</TargetFilename>
                <TargetFilename condition="contains">Users</TargetFilename>
                <TargetFilename condition="end with">.vb</TargetFilename>
                <TargetFilename condition="end with">.vbe</TargetFilename>
                <TargetFilename condition="end with">.vbs</TargetFilename>
            </FileCreateStreamHash>
        </RuleGroup>"""
            },
            "SuspiciousNamedPipes": {
                "id": 17,
                "name": "17) +可疑命名管道创建及通信",
                "content": r"""<RuleGroup name="SuspiciousNamedPipes" groupRelation="or">
            <PipeEvent onmatch="include">
                <PipeName condition="contains">msagent</PipeName>
                <PipeName condition="contains">c2</PipeName>
                <PipeName condition="contains">malleable</PipeName>
                <PipeName condition="contains">empire</PipeName>
                <PipeName condition="not begin with">\\.\pipe\lsass</PipeName>
                <PipeName condition="not begin with">\\.\pipe\winlogon</PipeName>
            </PipeEvent>
        </RuleGroup>
"""
            },
            "NamedPipesEventIncludes": {
                "id": 17,
                "name": "17、18) +命名管道创建及通信",
                "content": r"""<RuleGroup name="NamedPipesEventIncludes" groupRelation="or">
            <PipeEvent onmatch="include">
                <Rule groupRelation="and">
                    <PipeName condition="begin with">\</PipeName>
                    <EventType>CreatePipe</EventType>
                </Rule>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\atsvc</PipeName>
                <Rule groupRelation="and">
                    <PipeName name="SMB/Windows Admin Shares" condition="begin with">\msse-</PipeName>
                    <PipeName name="SMB/Windows Admin Shares" condition="end with">-server</PipeName>
                </Rule>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\msagent_</PipeName>
                <PipeName name="Possible Cobalt Strike post-exploitation jobs." condition="begin with">\postex_</PipeName>
                <PipeName name="Remote Services: SSH" condition="begin with">\postex_ssh_</PipeName>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\status_</PipeName>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\gruntsvc</PipeName>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\svcctl</PipeName>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\msf-pipe</PipeName>
                <Rule groupRelation="and">
                    <PipeName name="PowerShell" condition="begin with">\PSHost</PipeName>
                    <Image condition="is not">powershell.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <PipeName name="PowerShell" condition="begin with">\PSHost</PipeName>
                    <Image condition="is not">powershell_ise.exe</Image>
                </Rule>
                <PipeName name="SMB/Windows Admin Shares" condition="begin with">\PSEXESVC</PipeName>
                <PipeName name="System Network Connections Discovery" condition="begin with">\srvsvc</PipeName>
                <Rule groupRelation="and">
                    <PipeName condition="begin with">\TSVCPIPE</PipeName>
                </Rule>
                <PipeName name="System Owner/User Discovery" condition="begin with">\winreg</PipeName>
            </PipeEvent>
        </RuleGroup>
"""
            },
            "NamedPipesEventExcludes": {
                "id": 17,
                "name": "17、18) -命名管道创建及通信",
                "content": r"""<RuleGroup name="NamedPipesEventExcludes" groupRelation="or">
            <PipeEvent onmatch="exclude">
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Common Files\Adobe\ARM\1.0\AdobeARM.exe</Image>
                    <PipeName condition="begin with">\32B6B37A-4A7D-4e00-95F2-</PipeName>
                    <PipeName condition="end with">thsnYaVieBoda</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Adobe\Acrobat Reader DC\Reader\AcroCEF\RdrCEF.exe</Image>
                    <PipeName condition="begin with">\com.adobe.reader.rna.;\mojo</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Common Files\Adobe\AdobeGCClient\AGMService.exe</Image>
                    <PipeName condition="begin with">\gc_pipe_</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Common Files\Adobe\Creative Cloud Libraries\libs\node.exe</Image>
                    <PipeName condition="begin with">\uv\</PipeName>
                </Rule>
                <Image condition="is">"C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe"</Image>
                <Rule groupRelation="and">
                    <Image condition="contains all"> C:\Users\;\AppData\Local\Programs\Call Manager\Call Manager.exe</Image>
                    <PipeName condition="begin with">\crashpad_;\mojo.;\uv\</PipeName>
                </Rule>
                <Image condition="contains all">C:\Program Files;\Citrix\ICA Client\SelfServicePlugin\SelfService.exe</Image>
                <Image condition="contains all">C:\Program Files;\Citrix\ICA Client\Receiver\Receiver.exe</Image>
                <Image condition="contains all">C:\Program Files;\Citrix\ICA Client\wfcrun32.exe</Image>
                <Image condition="contains all">C:\Program Files;\Citrix\ICA Client\concentr.exe</Image>
                <Image condition="contains all">C:\Users\;\AppData\Local\Citrix\ICA Client\receiver\Receiver.exe</Image>
                <Image condition="contains all">C:\Users\;\AppData\Local\Citrix\ICA Client\SelfServicePlugin\SelfService.exe</Image>
                <Image condition="contains all">C:\Program Files;\FireEye\xagt\xagt.exe</Image>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Google\Update\Install\;setup.exe</Image>
                    <PipeName condition="begin with">\crashpad_</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Google\Chrome\Application\chrome.exe</Image>
                    <PipeName condition="begin with">\mojo.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Google\Chrome\Application\;\Installer\chrmstp.exe</Image>
                    <PipeName condition="begin with">\crashpad_</PipeName>
                </Rule>
                <PipeName condition="begin with">\Vivisimo Velocity</PipeName>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Microsoft\Edge\Application\msedge.exe</Image>
                    <PipeName condition="begin with">\LOCAL\mojo.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Microsoft\Edge\Application\msedge.exe</Image>
                    <PipeName condition="begin with">\LOCAL\chrome.sync.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Microsoft\Edge\Application\msedge.exe</Image>
                    <PipeName condition="begin with">\LOCAL\crashpad_</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Microsoft Office\root\Office16\OUTLOOK.EXE</Image>
                    <PipeName condition="is">\MsFteWds</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Users\;\AppData\Local\Microsoft\Teams\current\Teams.exe</Image>
                    <PipeName condition="begin with">\mojo.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Users\;\AppData\Local\Microsoft\Teams\current\Teams.exe</Image>
                    <PipeName condition="begin with">\chrome.sync.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Mozilla Firefox\firefox.exe</Image>
                    <PipeName condition="begin with">\cubeb-pipe-</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Mozilla Firefox\firefox.exe</Image>
                    <PipeName condition="begin with">\chrome.</PipeName>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="contains all">C:\Program Files;\Mozilla Firefox\firefox.exe</Image>
                    <PipeName condition="begin with">\gecko-crash-server-pipe.</PipeName>
                </Rule>
                <PipeName condition="is">\SQLLocal\MSSQLSERVER</PipeName>
                <PipeName condition="is">\SQLLocal\INSTANCE01</PipeName>
                <PipeName condition="is">\SQLLocal\SQLEXPRESS</PipeName>
                <PipeName condition="is">\SQLLocal\COMMVAULT</PipeName>
                <PipeName condition="is">\SQLLocal\RTCLOCAL</PipeName>
                <PipeName condition="is">\SQLLocal\RTC</PipeName>
                <PipeName condition="is">\SQLLocal\TMSM</PipeName>
                <Image condition="is">Program Files (x86)\Microsoft SQL Server\110\DTS\binn\dtexec.exe</Image>
                <Image condition="end with">PostgreSQL\9.6\bin\postgres.exe</Image>
                <PipeName condition="contains">\pgsignal_</PipeName>
                <Image condition="is">Program Files\Qlik\Sense\Engine\Engine.exe</Image>
                <Image condition="contains all">C:\Program Files;\Qualys\QualysAgent\QualysAgent.exe</Image>
                <Image condition="end with">Program Files\SplunkUniversalForwarder\bin\splunkd.exe</Image>
                <Image condition="end with">Program Files\SplunkUniversalForwarder\bin\splunk.exe</Image>
                <Image condition="end with">Program Files\SplunkUniversalForwarder\bin\splunk-MonitorNoHandle.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\CMAgent\OfcCMAgent.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\web\service\ofcservice.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\Web\Service\DbServer.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\web\service\verconn.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\WEB_OSCE\WEB\CGI\cgiOnClose.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\WEB_OSCE\WEB\CGI\cgiRqHotFix.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\LWCS\LWCSService.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\WSS\iCRCService.exe</Image>
                <Image condition="end with">Program Files\Trend\SPROTECT\x64\tsc.exe</Image>
                <Image condition="end with">Program Files\Trend\SPROTECT\x64\tsc64.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\web\service\osceintegrationservice.exe</Image>
                <Image condition="end with">Program Files (x86)\Trend Micro\OfficeScan\PCCSRV\web\service\OfcLogReceiverSvc.exe</Image>
                <PipeName condition="is">\Trend Micro OSCE Command Handler Manager</PipeName>
                <PipeName condition="is">\Trend Micro OSCE Command Handler2 Manager</PipeName>
                <PipeName condition="is">\Trend Micro Endpoint Encryption ToolBox Command Handler Manager</PipeName>
                <PipeName condition="is">\OfcServerNamePipe</PipeName>
                <PipeName condition="is">\ntapvsrq</PipeName>
                <PipeName condition="is">\srvsvc</PipeName>
                <PipeName condition="is">\wkssvc</PipeName>
                <PipeName condition="is">\lsass</PipeName>
                <PipeName condition="is">\winreg</PipeName>
                <PipeName condition="is">\spoolss</PipeName>
                <PipeName condition="contains">Anonymous Pipe</PipeName>
                <Image condition="is">c:\windows\system32\inetsrv\w3wp.exe</Image>
            </PipeEvent>
        </RuleGroup>"""
            },
            "WmiEventIncludes": {
                "id": 19,
                "name": "19、20、21) +WMI 事件活动",
                "content": r"""<RuleGroup name="WmiEventIncludes" groupRelation="or">
            <WmiEvent onmatch="include">
                <Operation name="Windows Management Instrumentation" condition="is">Created</Operation>
            </WmiEvent>
        </RuleGroup>
"""
            },
            "DnsQueryExcludes": {
                "id": 22,
                "name": "22) -DNS 查询",
                "content": r"""<RuleGroup name="DnsQueryExcludes" groupRelation="or">
            <DnsQuery onmatch="exclude">
                <QueryName condition="end with">.iana.org</QueryName>
                <QueryName condition="end with">.icann.org</QueryName>
                <QueryName condition="end with">cloudflare-dns.com</QueryName>
                <QueryName condition="end with">google-public-dns.com</QueryName>
                <QueryName condition="end with">ntp.org</QueryName>
                <QueryName condition="is">public-dns-a.alidns.com</QueryName>
                <QueryName condition="is">public-dns-b.alidns.com</QueryName>
                <QueryName condition="end with">.teams.microsoft.com</QueryName>
                <QueryName condition="end with">.onedrive.live.com</QueryName>
                <QueryName condition="end with">.apple.com</QueryName>
                <QueryName condition="end with">.icloud.com</QueryName>
                <QueryName condition="end with">.appstore.com</QueryName>
                <QueryName condition="end with">.dell.com</QueryName>
                <QueryName condition="end with">.hp.com</QueryName>
                <QueryName condition="end with">.lenovo.com</QueryName>
                <QueryName condition="end with">.qq.com</QueryName>
                <QueryName condition="end with">.weixin.qq.com</QueryName>
                <QueryName condition="end with">.taobao.com</QueryName>
                <QueryName condition="end with">.alipay.com</QueryName>
                <QueryName condition="end with">.163.com</QueryName>
                <QueryName condition="end with">.netease.com</QueryName>
                <QueryName condition="end with">.google.com</QueryName>
                <QueryName condition="end with">.gmail.com</QueryName>
                <QueryName condition="end with">.slack.com</QueryName>
                <QueryName condition="end with">.zoom.us</QueryName>
                <QueryName condition="end with">.notion.so</QueryName>
                <QueryName condition="end with">.symantec.com</QueryName>
                <QueryName condition="end with">.mcafee.com</QueryName>
                <QueryName condition="end with">.kaspersky.com</QueryName>
                <QueryName condition="end with">.1password.com</QueryName>
                <QueryName condition="end with">.lastpass.com</QueryName>
                <QueryName condition="end with">.gov.cn</QueryName>
                <QueryName condition="end with">.edu.cn</QueryName>
                <QueryName condition="end with">.ac.cn</QueryName>
                <QueryName condition="end with">.unionpay.com</QueryName>
                <QueryName condition="end with">.arpa.</QueryName>
                <QueryName condition="end with">.arpa</QueryName>
                <QueryName condition="end with">.msftncsi.com</QueryName>
                <QueryName condition="is">..localmachine</QueryName>
                <QueryName condition="is">localhost</QueryName>
                <QueryName condition="end with">-pushp.svc.ms</QueryName>
                <QueryName condition="end with">.b-msedge.net</QueryName>
                <QueryName condition="end with">.bing.com</QueryName>
                <QueryName condition="end with">.hotmail.com</QueryName>
                <QueryName condition="end with">.live.com</QueryName>
                <QueryName condition="end with">.live.net</QueryName>
                <QueryName condition="end with">.s-microsoft.com</QueryName>
                <QueryName condition="end with">.microsoft.com</QueryName>
                <QueryName condition="end with">.microsoftonline.com</QueryName>
                <QueryName condition="end with">.microsoftstore.com</QueryName>
                <QueryName condition="end with">.ms-acdc.office.com</QueryName>
                <QueryName condition="end with">.msedge.net</QueryName>
                <QueryName condition="end with">.msn.com</QueryName>
                <QueryName condition="end with">.msocdn.com</QueryName>
                <QueryName condition="end with">.skype.com</QueryName>
                <QueryName condition="end with">.skype.net</QueryName>
                <QueryName condition="end with">.windows.com</QueryName>
                <QueryName condition="end with">.windows.net.nsatc.net</QueryName>
                <QueryName condition="end with">.windowsupdate.com</QueryName>
                <QueryName condition="end with">.xboxlive.com</QueryName>
                <QueryName condition="is">login.windows.net</QueryName>
                <Image condition="begin with">C:\ProgramData\Microsoft\Windows Defender\Platform\</Image>
            </DnsQuery>
        </RuleGroup>"""
            },
            "DnsQueryIncludes": {
                "id": 22,
                "name": "22) +DNS 查询",
                "content": r"""<RuleGroup name="DnsQueryIncludes" groupRelation="or">
            <DnsQuery onmatch="include">
                <QueryName condition="contains"></QueryName>
            </DnsQuery>
        </RuleGroup>"""
            },
            "FileDelete": {
                "id": 23,
                "name": "23) +文件删除（已归档，记录删除的文件路径、哈希，且对文件进行归档备份）",
                "content": r"""<RuleGroup groupRelation="or">
            <FileDelete onmatch="include">
                <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </FileDelete>
        </RuleGroup>"""
            },
            "ClipboardChange": {
                "id": 24,
                "name": "24) +剪贴板变更（记录修改剪贴板的进程、内容哈希，检测敏感数据拷贝）",
                "content": r"""<RuleGroup name="ClipboardChange" groupRelation="or">
            <ClipboardChange onmatch="include" />
        </RuleGroup>
"""
            },
            "ProcessTamperingExcludes": {
                "id": 25,
                "name": "25) -进程镜像篡改（检测进程文件被修改的行为，如注入代码后文件完整性破坏）",
                "content": r"""<RuleGroup name="ProcessTampering" groupRelation="or">
            <ProcessTampering onmatch="exclude">
                <Image condition="is">C:\Program Files\Mozilla Firefox\firefox.exe</Image>
                <Image condition="is">C:\Program Files\Mozilla Firefox\updater.exe</Image>
                <Image condition="is">C:\Program Files\Mozilla Firefox\default-browser-agent.exe</Image>
                <Image condition="is">C:\Program Files\Mozilla Firefox\pingsender.exe</Image>
                <Image condition="is">C:\Program Files\Git\cmd\git.exe</Image>
                <Image condition="is">C:\Program Files\Git\mingw64\bin\git.exe</Image>
                <Image condition="is">C:\Program Files\Git\mingw64\libexec\git-core\git.exe</Image>
                <Image condition="is">C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe</Image>
                <Rule groupRelation="and">
                    <Image condition="begin with">C:\Program Files (x86)\Microsoft\Edge\Application\</Image>
                    <Image condition="end with">\BHO\ie_to_edge_stub.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="begin with">C:\Program Files (x86)\Microsoft\Edge\Application\</Image>
                    <Image condition="end with">\identity_helper.exe</Image>
                </Rule>
                <Rule groupRelation="and">
                    <Image condition="begin with">C:\Program Files (x86)\Microsoft\EdgeUpdate\Install\</Image>
                    <Image condition="contains">\MicrosoftEdge_X64_</Image>
                </Rule>
                <Image condition="is">C:\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\bin\XDelta64\xdelta3.exe</Image>
                <Image condition="contains">unknown process</Image>
                <Image condition="is">C:\Program Files\Microsoft VS Code\Code.exe</Image>
                <Image condition="is">C:\Windows\System32\wbem\WMIADAP.exe</Image>
            </ProcessTampering>
        </RuleGroup>"""
            },
            "ProcessTamperingIncludes": {
                "id": 25,
                "name": "25) +进程镜像篡改（检测进程文件被修改的行为，如注入代码后文件完整性破坏）",
                "content": r"""<RuleGroup name="ProcessTampering" groupRelation="or">
            <ProcessTampering onmatch="include">
            </ProcessTampering>
        </RuleGroup>"""
            },
            "FileDeleteDetected": {
                "id": 26,
                "name": "26) +文件删除（仅记录，不归档，记录删除的文件路径、哈希、是否为可执行文件）",
                "content": r"""<RuleGroup groupRelation="or">
            <FileDeleteDetected onmatch="include">
                <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </FileDeleteDetected>
        </RuleGroup>"""
            },
            "FileBlockExecutable": {
                "id": 27,
                "name": "27) +可执行文件阻止（阻断特定可执行文件运行，记录被阻止的文件路径、所属进程）",
                "content": r"""<RuleGroup groupRelation="or">
            <FileBlockExecutable onmatch="include" />
        </RuleGroup>"""
            },
            "FileBlockShredding": {
                "id": 28,
                "name": "28) +文件粉碎阻止（阻断文件粉碎工具删除文件的行为，防止证据销毁）",
                "content": r"""<RuleGroup groupRelation="or">
            <FileBlockShredding onmatch="include" />
        </RuleGroup>"""
            },
            "FileExecutableDetected": {
                "id": 29,
                "name": "29) +可执行文件检测（记录新创建的可执行文件路径、哈希、所属进程）",
                "content": r"""<RuleGroup groupRelation="or">
            <FileExecutableDetected onmatch="include" />
        </RuleGroup>"""
            }
        }
    
    def _create_widgets(self):
        """创建界面组件（支持编辑功能）"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧：规则组选择（按ID排序）
        left_frame = ttk.LabelFrame(main_frame, text="监控模块（按事件ID排序）", padding="10")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 10))
        
        # 按ID排序规则组
        self.sorted_rules = sorted(self.rule_templates.items(), key=lambda x: (x[1]["id"], x[0]))
        
        # 创建复选框
        for key, rule in self.sorted_rules:
            var = tk.BooleanVar(value=True)
            var.trace_add("write", lambda *args: self.update_preview())
            self.rule_groups[key] = var
            
            cb = ttk.Checkbutton(
                left_frame, 
                text=rule["name"], 
                variable=var,
                command=self.update_preview
            )
            cb.pack(anchor=tk.W, pady=2)
        
        # 哈希算法选择
        hash_frame = ttk.LabelFrame(left_frame, text="哈希算法", padding="5")
        hash_frame.pack(fill=tk.X, pady=10)
        
        self.hash_md5 = tk.BooleanVar(value=True)
        self.hash_sha1 = tk.BooleanVar(value=False)
        self.hash_sha256 = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(hash_frame, text="MD5", variable=self.hash_md5, command=self.update_preview).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(hash_frame, text="SHA1", variable=self.hash_sha1, command=self.update_preview).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(hash_frame, text="SHA256", variable=self.hash_sha256, command=self.update_preview).pack(side=tk.LEFT, padx=5)
        
        # 证书吊销检查
        self.check_revocation = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            left_frame, 
            text="启用证书吊销检查", 
            variable=self.check_revocation,
            command=self.update_preview
        ).pack(anchor=tk.W, pady=10)
        
        # 按钮区
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="全选", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="全不选", command=self.deselect_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存配置", command=self.save_config).pack(side=tk.LEFT, padx=5)
        
        # 右侧：编辑与预览区域
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 预览/编辑选项
        preview_ctrl_frame = ttk.Frame(right_frame)
        preview_ctrl_frame.pack(fill=tk.X)
        
        self.preview_mode = tk.StringVar(value="all")
        ttk.Radiobutton(preview_ctrl_frame, text="完整配置", variable=self.preview_mode, value="all", command=self.switch_preview_mode).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(preview_ctrl_frame, text="选中模块", variable=self.preview_mode, value="selected", command=self.switch_preview_mode).pack(side=tk.LEFT)
        ttk.Radiobutton(preview_ctrl_frame, text="单个模块", variable=self.preview_mode, value="single", command=self.switch_preview_mode).pack(side=tk.LEFT)
        
        # 模块选择下拉框（仅单个模块模式可见）
        self.module_select_frame = ttk.Frame(preview_ctrl_frame)
        ttk.Label(self.module_select_frame, text="模块:").pack(side=tk.LEFT, padx=(10, 5))
        self.module_combobox = ttk.Combobox(self.module_select_frame, state="readonly", width=40)
        self.module_combobox['values'] = [rule["name"] for _, rule in self.sorted_rules]
        self.module_combobox.current(0)
        self.module_combobox.pack(side=tk.LEFT, padx=5)
        self.module_combobox.bind("<<ComboboxSelected>>", lambda e: self.update_preview())
        self.module_select_frame.pack(side=tk.LEFT)
        
        # 编辑控制按钮
        edit_ctrl_frame = ttk.Frame(right_frame)
        edit_ctrl_frame.pack(fill=tk.X)
        
        ttk.Button(edit_ctrl_frame, text="应用修改", command=self.apply_edits).pack(side=tk.RIGHT, padx=5)
        ttk.Label(edit_ctrl_frame, text="编辑区域:").pack(side=tk.LEFT, padx=(0, 10))
        
        # 可编辑的文本区域
        self.edit_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=80, height=40)
        self.edit_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 初始隐藏单个模块选择框
        self.switch_preview_mode()
    
    def switch_preview_mode(self):
        """切换预览模式并控制控件显示"""
        mode = self.preview_mode.get()
        if mode == "single":
            self.module_select_frame.pack(side=tk.LEFT)
        else:
            self.module_select_frame.pack_forget()
        self.update_preview()
    
    def select_all(self):
        for var in self.rule_groups.values():
            var.set(True)
        self.update_preview()
    
    def deselect_all(self):
        for var in self.rule_groups.values():
            var.set(False)
        self.update_preview()
    
    def get_selected_rules(self):
        """按ID顺序获取选中的规则"""
        selected = []
        for key, rule in self.sorted_rules:
            if self.rule_groups[key].get():
                selected.append((key, rule))
        return selected
    
    def get_hash_algorithms(self):
        hashes = []
        if self.hash_md5.get():
            hashes.append("md5")
        if self.hash_sha1.get():
            hashes.append("sha1")
        if self.hash_sha256.get():
            hashes.append("sha256")
        return ",".join(hashes) if hashes else "md5"
    
    def generate_full_config(self, pretty=True):
        """用XML结构化生成完整配置"""
        # 创建根元素
        sysmon = ET.Element("Sysmon")
        sysmon.set("schemaversion", "4.90")
        
        # 添加元数据
        ET.SubElement(sysmon, "HashAlgorithms").text = self.get_hash_algorithms()
        if self.check_revocation.get():
            ET.SubElement(sysmon, "CheckRevocation")
        
        # 添加事件过滤
        event_filtering = ET.SubElement(sysmon, "EventFiltering")
        
        # 添加选中的规则组
        for key, rule in self.get_selected_rules():
            # 解析规则组XML
            try:
                rule_root = ET.fromstring(rule["content"])
                event_filtering.append(rule_root)
            except Exception as e:
                messagebox.showerror("解析错误", f"模块 {rule['name']} 内容格式错误：{str(e)}")
        
        # 格式化XML
        rough_string = ET.tostring(sysmon, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        
        # 处理缩进和空行
        if pretty:
            xml_str = reparsed.toprettyxml(indent="    ", encoding="utf-8").decode("utf-8")
            # 移除多余空行
            xml_str = re.sub(r'\n\s*\n', '\n', xml_str.strip())
            return xml_str
        return rough_string.decode("utf-8")
    
    def update_preview(self):
        """更新编辑区域内容（按当前模式）"""
        current_text = self.edit_text.get(1.0, tk.END).rstrip()
        self.edit_text.delete(1.0, tk.END)
        
        mode = self.preview_mode.get()
        if mode == "all":
            # 显示完整配置
            self.current_edit_mode = "all"
            self.edit_text.insert(tk.END, self.generate_full_config())
        elif mode == "selected":
            # 显示选中的模块
            self.current_edit_mode = "selected"
            selected_rules = [rule["content"] for _, rule in self.get_selected_rules()]
            self.edit_text.insert(tk.END, "\n\n".join(selected_rules))
        else:
            # 显示单个模块
            self.current_edit_mode = "single"
            selected_name = self.module_combobox.get()
            for key, rule in self.rule_templates.items():
                if rule["name"] == selected_name:
                    self.edit_text.insert(tk.END, rule["content"])
                    break
    
    def apply_edits(self):
        """应用编辑内容到规则模板"""
        edited_text = self.edit_text.get(1.0, tk.END).rstrip()
        if not edited_text:
            return
        
        try:
            if self.current_edit_mode == "single":
                # 单个模块编辑
                selected_name = self.module_combobox.get()
                for key, rule in self.rule_templates.items():
                    if rule["name"] == selected_name:
                        # 验证XML格式
                        ET.fromstring(edited_text)
                        self.rule_templates[key]["content"] = edited_text
                        messagebox.showinfo("成功", f"模块「{selected_name}」已更新")
                        break
            elif self.current_edit_mode == "all":
                # 完整配置编辑（替换整个配置）
                root = ET.fromstring(edited_text)
                event_filtering = root.find("EventFiltering")
                if event_filtering is not None:
                    for rule_elem in event_filtering:
                        rule_name = rule_elem.get("name")
                        # 跳过无name属性的元素（避免NoneType错误）
                        if rule_name is None:
                            continue
                        # 查找匹配的规则组并更新
                        for key, rule in self.rule_templates.items():
                            if rule_name in rule["content"]:
                                self.rule_templates[key]["content"] = ET.tostring(rule_elem, 'utf-8').decode("utf-8")
                messagebox.showinfo("成功", "完整配置已更新（元数据仍通过界面设置）")
            else:
                # 选中模块批量编辑（按顺序更新）
                selected_rules = self.get_selected_rules()
                edited_rules = re.split(r'\n\n+(?=<RuleGroup)', edited_text)
                if len(edited_rules) == len(selected_rules):
                    for i, (key, rule) in enumerate(selected_rules):
                        ET.fromstring(edited_rules[i])  # 验证格式
                        self.rule_templates[key]["content"] = edited_rules[i]
                    messagebox.showinfo("成功", f"{len(selected_rules)}个选中模块已更新")
                else:
                    messagebox.showerror("错误", "编辑内容与选中模块数量不匹配")
        except Exception as e:
            messagebox.showerror("编辑错误", f"XML格式错误：{str(e)}")
        
        self.update_preview()
    
    def save_config(self):
        """保存格式化后的配置文件"""
        # 先应用当前编辑内容
        self.apply_edits()
        
        # 生成美观的XML
        try:
            config = self.generate_full_config()
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".xml",
                filetypes=[("XML文件", "*.xml"), ("所有文件", "*.*")],
                title="保存Sysmon配置文件"
            )
            
            if file_path:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(config)
                messagebox.showinfo("成功", f"配置文件已保存到:\n{file_path}")
        except Exception as e:
            messagebox.showerror("保存错误", f"保存失败：{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SysmonRuleGenerator(root)
    root.mainloop()