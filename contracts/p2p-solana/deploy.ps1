param(
    [string]$Cluster = "devnet",
    [string]$Deployer = (Join-Path $env:USERPROFILE ".config\solana\id.json"),
    [string]$ProgramKeypair = "",
    [switch]$Final
)
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root "target" }
$flags = @()
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    $tools = Get-ChildItem (Join-Path $env:USERPROFILE ".cache\solana") -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $tools) { throw "Install the Solana platform tools first: cargo-build-sbf --install-only" }
    $env:RUSTC = Join-Path $tools.FullName "platform-tools\rust\bin\rustc.exe"
    $flags += "--no-rustup-override", "--skip-tools-install"
}
Push-Location $root
try {
    cargo-build-sbf @flags
    if ($LASTEXITCODE -ne 0) { throw "The build failed" }
} finally {
    Pop-Location
}
$so = Join-Path $target "deploy\ego_escrow.so"
if (-not $ProgramKeypair) { $ProgramKeypair = Join-Path $target "deploy\ego_escrow-keypair.json" }
solana program deploy $so --program-id $ProgramKeypair --keypair $Deployer --url $Cluster
if ($LASTEXITCODE -ne 0) { throw "The deploy failed" }
$id = (solana address -k $ProgramKeypair).Trim()
if ($Final) {
    solana program set-upgrade-authority $id --final --keypair $Deployer --url $Cluster
    if ($LASTEXITCODE -ne 0) { throw "Locking the program failed" }
}
Write-Output "Escrow program: $id"
Write-Output "Set it as the solana network's escrow in %APPDATA%\EgoDesktop\market_networks.json, or in default_networks() for a release."
Write-Output "Keep $ProgramKeypair; it decides the program address."
