# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

<#
    .SYNOPSIS
    Stamps the project version.

    .DESCRIPTION
    CalVer YY.M.D.B, where B is a within-day ten-minute bucket computed as
    hour * 10 + minute / 10, giving 0 to 235.

    The clock is UTC. A local clock would make the same commit stamp
    differently depending on where it was built and would jump backwards
    twice a year at the daylight-saving boundary, which breaks the ordering
    the version is supposed to carry.

    Two files are written:
      VERSION      the canonical four-component string
      Cargo.toml   the three-component SemVer projection Cargo accepts

    Cargo takes only three components, so the workspace manifest carries
    YY.M.D. The installer needs B as well and reads VERSION directly.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Stamp a specific UTC instant instead of now. Used by tests.
    [datetime]$Instant
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

if ($PSBoundParameters.ContainsKey('Instant')) {
    $now = $Instant.ToUniversalTime()
} else {
    $now = [datetime]::UtcNow
}

$bucket = $now.Hour * 10 + [math]::Floor($now.Minute / 10)
$projectVersion = "{0}.{1}.{2}.{3}" -f ($now.Year - 2000), $now.Month, $now.Day, $bucket
$cargoVersion = "{0}.{1}.{2}" -f ($now.Year - 2000), $now.Month, $now.Day

$versionFile = Join-Path $repositoryRoot 'VERSION'
$manifest = Join-Path $repositoryRoot 'Cargo.toml'

if (-not $PSCmdlet.ShouldProcess($repositoryRoot, "Stamp version $projectVersion")) {
    return
}

# No trailing newline games: one line, LF, as the sibling repositories store it.
[IO.File]::WriteAllText($versionFile, "$projectVersion`n")

# Rewrite only the first top-level version line, which is the one in
# [workspace.package]; members inherit it.
$lines = [IO.File]::ReadAllLines($manifest)
$replaced = $false
for ($i = 0; $i -lt $lines.Length; $i++) {
    if (-not $replaced -and $lines[$i] -match '^version\s*=\s*"[^"]*"') {
        $lines[$i] = "version = `"$cargoVersion`""
        $replaced = $true
    }
}
if (-not $replaced) {
    throw "No top-level version line found in $manifest."
}
[IO.File]::WriteAllLines($manifest, $lines)

Write-Host "VERSION    $projectVersion"
Write-Host "Cargo.toml $cargoVersion"
