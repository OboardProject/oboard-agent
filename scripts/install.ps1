# Bootstrap for the Windows Agent installer. It only fetches the installer
# that the Controller serves at /install/agent.ps1 and runs it with the
# requested action; every download, signature check, and service change happens
# there. Run it from an elevated Windows PowerShell:
#
#   $env:OBOARD_CONTROLLER_URL = 'https://panel.example.com'
#   $env:OBOARD_ENROLL_TOKEN = '安装令牌'
#   & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/OboardProject/oboard-agent/main/scripts/install.ps1')))
#
# Set OBOARD_ACTION to update or uninstall for the other operations.

$ErrorActionPreference = 'Stop'

$controller = if ($env:OBOARD_CONTROLLER_URL) { $env:OBOARD_CONTROLLER_URL.Trim().TrimEnd('/') } else { '' }
if (-not $controller) {
    Write-Host '缺少主控地址。请从面板复制服务器的 Windows 安装命令，或先设置 $env:OBOARD_CONTROLLER_URL。' -ForegroundColor Red
    return
}
$action = if ($env:OBOARD_ACTION) { $env:OBOARD_ACTION.Trim().ToLowerInvariant() } else { 'install' }
if ($action -notin @('install', 'update', 'uninstall')) {
    Write-Host "不支持的操作：$action（可用：install、update、uninstall）" -ForegroundColor Red
    return
}
if ($action -eq 'install' -and -not $env:OBOARD_ENROLL_TOKEN) {
    Write-Host '安装 Agent 需要面板生成的一次性安装令牌。请先在主控面板添加服务器，再复制该服务器的安装命令。' -ForegroundColor Red
    return
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$client = New-Object Net.WebClient
$client.Encoding = [Text.Encoding]::UTF8
try {
    $installer = $client.DownloadString("$controller/install/agent.ps1")
} catch {
    Write-Host '无法从主控下载安装程序，请确认主控地址和网络连接后重试。' -ForegroundColor Red
    return
}
$env:OBOARD_ACTION = $action
& ([scriptblock]::Create($installer))
