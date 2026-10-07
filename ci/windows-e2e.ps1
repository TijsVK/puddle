# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
Runs puddle's real-machine VM tests (tier R) on a real Windows machine and posts the result as
the commit status `puddle/windows-e2e`.

.DESCRIPTION
Tier R covers what the hosted runners can't: a real client OS on mains power, sleep/resume,
Defender, the corporate network. The tests live in crates/puddle-vm-tests and are named
`vm_machine_*`; -All also runs the K/W set the CI jobs run.

Steps: power check (refuses on battery below -MinBattery percent), per-run prefix, private msb
home under -Root, `cargo nextest run --profile vm`, the msb fork's regression repros
(ci/msb-repros, see -MsbRepros), commit status. VM tests are never retried.
-WhatIf prints every step without booting a VM or posting a status.

Windows PowerShell 5.1 compatible; keep this file ASCII-only.

.PARAMETER RuntimeDir
Directory with msb.exe and libkrunfw.dll (the fork tag's release assets, e.g. from ci/fetch-msb.sh
in Git Bash). Defaults to $env:PUDDLE_VM_RUNTIME_DIR.

.PARAMETER Filter
nextest filter expression for the tests to run. Default: the real-machine tests.

.PARAMETER All
Run every VM test (real-machine and CI ones) instead of -Filter.

.PARAMETER MsbRepros
Cases of ci/msb-repros/repros.ps1 to run against the runtime's msb.exe after the nextest run:
relay, signal, scp, forward, stale-dir (default: all), or 'none'. They pin the fixes the puddle
fork of msb carries; stock msb fails them. Not run in -Bisect steps.

.PARAMETER ReproPort
Local port for the relay repro's `ssh -L`. Default 18190; give parallel runs different ports.

.PARAMETER Prefix
Run prefix (lowercase letters, digits, '-', at most 20, starts with a letter). Default:
l<yyMMddHHmmss>. Three runs at once need three prefixes; the default differs per second.

.PARAMETER Root
Directory the private msb home goes under. Default: $env:TEMP\pvm.

.PARAMETER MinBattery
Battery percentage below which a run on battery is refused. Default 30.

.PARAMETER NoStatus
Don't post the commit status (local experiments; bisect steps never post).

.PARAMETER Repo
GitHub repo for the status. Default TijsVK/puddle.

.PARAMETER Bisect
Find the first bad commit between -Good and -Bad with `git bisect run`, using this script as the
test. Exit codes per step: 0 good, 1 bad, 125 skip (power refused, build failed).

.PARAMETER Good
Known-good commit for -Bisect.

.PARAMETER Bad
Known-bad commit for -Bisect. Default HEAD.

.PARAMETER BisectStep
Internal: set by -Bisect for each step.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File ci\windows-e2e.ps1 -RuntimeDir C:\puddle\msb-0.7.7-puddle.12

.EXAMPLE
powershell -ExecutionPolicy Bypass -File ci\windows-e2e.ps1 -WhatIf

.EXAMPLE
powershell -ExecutionPolicy Bypass -File ci\windows-e2e.ps1 -Bisect -Good v0.1.0 -All
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RuntimeDir = $env:PUDDLE_VM_RUNTIME_DIR,
    [string]$Filter = 'test(/(^|::)vm_machine_/)',
    [switch]$All,
    [string[]]$MsbRepros = @('relay', 'signal', 'scp', 'forward', 'stale-dir'),
    [int]$ReproPort = 18190,
    [string]$Prefix = ('l' + (Get-Date -Format 'yyMMddHHmmss')),
    [string]$Root = (Join-Path $env:TEMP 'pvm'),
    [int]$MinBattery = 30,
    [switch]$NoStatus,
    [string]$Repo = 'TijsVK/puddle',
    [switch]$Bisect,
    [string]$Good,
    [string]$Bad = 'HEAD',
    [switch]$BisectStep
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Exit codes. 125 is git bisect's "skip this commit".
$ExitPass = 0
$ExitFail = 1
$ExitUsage = 2
$ExitRefused = 3
$ExitSkip = 125
$StatusContext = 'puddle/windows-e2e'
$AmbientMsbVars = @('MSB_PATH', 'MSB_LIBKRUNFW_PATH', 'MSB_AGENTD_PATH', 'MSB_HOME', 'MSB_CONFIG_PATH')

function Write-Step([string]$Text) { Write-Host "==> $Text" }

# Reports a refusal and ends the script. (Write-Error would throw under 'Stop' and lose the code.)
function Exit-With([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("windows-e2e: $Message")
    exit $Code
}

# Load the CIM cmdlets with -WhatIf off: under -WhatIf their auto-import prints 'What if' noise.
$whatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module CimCmdlets
$WhatIfPreference = $whatIf

# Runs a native command with its output on the console; returns only its exit code. Native stderr
# must not become a terminating error under 'Stop' (PowerShell 5.1), so the preference is relaxed
# around the call.
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe @Arguments 2>&1 | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
}

# Power state as an object: OnBattery, Percent, Text. A desktop without a battery is on mains.
function Get-PowerState {
    $batteries = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
    if ($batteries.Count -eq 0) {
        return [pscustomobject]@{ OnBattery = $false; Percent = 100; Text = 'mains (no battery)' }
    }
    $b = $batteries[0]
    # BatteryStatus 1 = discharging, 4 = low, 5 = critical: all mean running on the battery.
    $onBattery = @(1, 4, 5) -contains [int]$b.BatteryStatus
    $percent = [int]$b.EstimatedChargeRemaining
    $where = if ($onBattery) { 'battery' } else { 'mains' }
    return [pscustomobject]@{
        OnBattery = $onBattery
        Percent = $percent
        Text = "$where, $percent% (BatteryStatus $($b.BatteryStatus))"
    }
}

function Test-Prefix([string]$Value) {
    return ($Value -cmatch '^[a-z][a-z0-9-]{0,19}$') -and -not $Value.EndsWith('-')
}

function Get-RepoRoot {
    $root = (& git -C $PSScriptRoot rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $root) { throw "not inside a git checkout: $PSScriptRoot" }
    return $root.Trim()
}

function Set-CommitStatus([string]$Sha, [string]$State, [string]$Description) {
    if ($NoStatus -or $BisectStep) { return }
    $target = "$Repo@$($Sha.Substring(0, 12))"
    if ($PSCmdlet.ShouldProcess($target, "post status $StatusContext=$State ($Description)")) {
        $code = Invoke-Native 'gh' @('api', '-X', 'POST', "repos/$Repo/statuses/$Sha",
            '-f', "state=$State", '-f', "context=$StatusContext", '-f', "description=$Description")
        if ($code -ne 0) { Write-Warning "posting the commit status failed (gh exit $code)" }
    }
}

# --- Bisect driver -----------------------------------------------------------------------------
if ($Bisect) {
    if (-not $Good) { Exit-With $ExitUsage '-Bisect needs -Good <commit>' }
    $repoRoot = Get-RepoRoot
    # Older commits may not have this script (or have another version): run a copy.
    $copy = Join-Path $env:TEMP "puddle-windows-e2e-bisect-$PID.ps1"
    $stepArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $copy, '-BisectStep',
        '-RuntimeDir', $RuntimeDir, '-Root', $Root, '-MinBattery', "$MinBattery")
    if ($All) { $stepArgs += '-All' } else { $stepArgs += @('-Filter', $Filter) }
    $powershell = Join-Path $PSHOME 'powershell.exe'
    Write-Step "bisect $Good..$Bad in $repoRoot, step: $powershell $($stepArgs -join ' ')"
    if (-not $PSCmdlet.ShouldProcess($repoRoot, "git bisect start $Bad $Good; git bisect run <step>; git bisect reset")) {
        exit $ExitPass
    }
    Copy-Item -LiteralPath $PSCommandPath -Destination $copy -Force
    Push-Location $repoRoot
    try {
        $code = Invoke-Native 'git' @('bisect', 'start', $Bad, $Good)
        if ($code -ne 0) { exit $ExitFail }
        $code = Invoke-Native 'git' (@('bisect', 'run', $powershell) + $stepArgs)
        Invoke-Native 'git' @('bisect', 'log') | Out-Null
        exit $code
    } finally {
        Invoke-Native 'git' @('bisect', 'reset') | Out-Null
        Pop-Location
        Write-Host "bisect step script copy left at $copy (delete it when done)"
    }
}

# --- One run -----------------------------------------------------------------------------------
$refused = if ($BisectStep) { $ExitSkip } else { $ExitRefused }

$power = Get-PowerState
Write-Step "POWER $($power.Text)"
if ($power.OnBattery -and $power.Percent -lt $MinBattery) {
    Exit-With $refused "on battery at $($power.Percent)% (below $MinBattery%): not starting VMs; plug in and rerun"
}

if (-not (Test-Prefix $Prefix)) {
    Exit-With $ExitUsage "invalid -Prefix '$Prefix': 1-20 lowercase letters, digits or '-', starting with a letter"
}
if (-not $RuntimeDir) {
    if ($WhatIfPreference) {
        $RuntimeDir = '<RuntimeDir>'
    } else {
        Exit-With $ExitUsage 'no runtime: pass -RuntimeDir or set PUDDLE_VM_RUNTIME_DIR (a folder with msb.exe + libkrunfw.dll)'
    }
} elseif (-not $WhatIfPreference) {
    foreach ($file in @('msb.exe', 'libkrunfw.dll')) {
        if (-not (Test-Path -LiteralPath (Join-Path $RuntimeDir $file) -PathType Leaf)) {
            Exit-With $ExitUsage "runtime dir $RuntimeDir has no $file"
        }
    }
}

$repoRoot = Get-RepoRoot
$sha = (& git -C $repoRoot rev-parse HEAD).Trim()
$dirty = [bool](& git -C $repoRoot status --porcelain --untracked-files=no)
Write-Step "commit $sha$(if ($dirty) { ' (uncommitted changes: no status will be posted)' })"

# The harness refuses ambient msb settings; drop them for this process and its children only.
foreach ($var in $AmbientMsbVars) {
    if (Test-Path "Env:$var") {
        Write-Step "unsetting $var for this run"
        Remove-Item "Env:$var"
    }
}
$env:PUDDLE_VM_RUNTIME_DIR = $RuntimeDir
$env:PUDDLE_VM_PREFIX = $Prefix
$env:PUDDLE_VM_ROOT = $Root
Write-Step "prefix $Prefix, msb home $(Join-Path $Root $Prefix), runtime $RuntimeDir"

$nextest = @('nextest', 'run', '-p', 'puddle-vm-tests', '--profile', 'vm', '--locked', '--no-tests=warn')
if (-not $All) { $nextest += @('-E', $Filter) }

# The msb fork's regression repros (vendored from the fork's tests/puddle, see ci/msb-repros/SOURCE).
$repros = @($MsbRepros | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($BisectStep -or $repros -contains 'none') { $repros = @() }
$reproArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $PSScriptRoot 'msb-repros\repros.ps1'),
    '-Msb', "$RuntimeDir\msb.exe", '-Libkrunfw', "$RuntimeDir\libkrunfw.dll",
    '-Case', ($repros -join ','), '-Prefix', "$Prefix-r", '-LocalPort', "$ReproPort",
    '-Work', (Join-Path $Root "$Prefix-repros"))
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$postStatus = -not $dirty
if ($postStatus) {
    Set-CommitStatus $sha 'pending' "running on $env:COMPUTERNAME ($($power.Text))"
}

Write-Step "cargo $($nextest -join ' ')"
if (-not $PSCmdlet.ShouldProcess($repoRoot, "cargo $($nextest -join ' ') (boots microVMs)")) {
    if ($repros.Count -gt 0) { Write-Step "msb repros: $powershell $($reproArgs -join ' ')" }
    if ($postStatus) { Set-CommitStatus $sha 'success' "<result> on $env:COMPUTERNAME" }
    Write-Step 'dry run: nothing booted, no status posted'
    exit $ExitPass
}

Push-Location $repoRoot
try {
    $build = Invoke-Native 'cargo' @('nextest', 'run', '-p', 'puddle-vm-tests', '--profile', 'vm', '--locked', '--no-run')
    if ($build -ne 0) {
        Write-Warning "build failed (cargo exit $build)"
        if ($postStatus) { Set-CommitStatus $sha 'error' "build failed on $env:COMPUTERNAME" }
        exit $(if ($BisectStep) { $ExitSkip } else { $ExitFail })
    }
    $code = Invoke-Native 'cargo' $nextest
} finally {
    Pop-Location
}

$reproCode = 0
if ($repros.Count -gt 0) {
    Write-Step "msb repros ($($repros -join ', ')): $powershell $($reproArgs -join ' ')"
    $reproCode = Invoke-Native $powershell $reproArgs
    Write-Step "msb repros exit $reproCode"
}

$power = Get-PowerState
Write-Step "POWER at the end: $($power.Text)"
if ($code -eq 0 -and $reproCode -eq 0) {
    if ($postStatus) { Set-CommitStatus $sha 'success' "L tests passed on $env:COMPUTERNAME ($($power.Text))" }
    Write-Step 'PASS'
    exit $ExitPass
}
if ($postStatus) { Set-CommitStatus $sha 'failure' "L tests failed on $env:COMPUTERNAME (nextest exit $code, msb repros exit $reproCode)" }
Write-Step "FAIL (nextest exit $code, msb repros exit $reproCode); msb logs stay under $(Join-Path $Root $Prefix) and $(Join-Path $Root "$Prefix-repros")"
exit $ExitFail
