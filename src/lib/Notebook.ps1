#Requires -Version 7.4
<#
    Notebook.ps1 - Jupyter notebook (.ipynb) code-cell projection.

    Ported from scan-python-packages v1.6.1. The notebook is parsed as JSON and
    NEVER executed. Only cell_type='code' cells are copied into a generated .py
    projection that downstream analyzers (Bandit/detect-secrets) then scan.
    Saved outputs and attachments are surfaced as parser findings because they
    are visible payloads but not executable Python code-cell input.

    Returns @{ Success; SourcePath; Findings } where Findings use the normalized
    schema (Tool='NotebookParser', Category='parser').
#>

Set-StrictMode -Version Latest

function New-NotebookFinding {
    param(
        [string]$RelPath,
        [ValidateSet('HIGH','MEDIUM','LOW','INFO')][string]$Severity,
        [string]$Issue,
        [string]$TestID,
        [int]$CellNumber = 0
    )
    New-Finding -Tool 'NotebookParser' -Category 'parser' -Severity $Severity `
        -Confidence 'HIGH' -UnitType 'python' -File $RelPath -Line $CellNumber `
        -Issue $Issue -TestID $TestID
}

function Convert-NotebookToPythonSource {
    <#
        Project a notebook's code cells into a .py file under $OutputRoot.
        $RelPath is used for finding file labels (defaults to the notebook name).
    #>
    param(
        [Parameter(Mandatory)][string]$NotebookPath,
        [Parameter(Mandatory)][string]$OutputRoot,
        [string]$OutputName = '',
        [string]$RelPath = ''
    )

    if (-not $RelPath) { $RelPath = Split-Path $NotebookPath -Leaf }
    $findings = [System.Collections.Generic.List[object]]::new()

    try {
        New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
        $notebook = Get-Content -LiteralPath $NotebookPath -Raw -Encoding utf8 | ConvertFrom-Json

        if (-not $notebook.PSObject.Properties['cells']) {
            $findings.Add((New-NotebookFinding -RelPath $RelPath -Severity 'HIGH' `
                -Issue 'Notebook JSON has no cells array; code cells could not be analyzed.' `
                -TestID 'NOTEBOOK-MALFORMED'))
            return @{ Success = $false; SourcePath = $null; Findings = $findings.ToArray() }
        }

        if (-not $OutputName) {
            $safeBase = ([IO.Path]::GetFileNameWithoutExtension($NotebookPath) -replace '[^\w\-.]', '_')
            if ([string]::IsNullOrWhiteSpace($safeBase)) { $safeBase = 'notebook' }
            $OutputName = "$safeBase.ipynb.py"
        }
        $sourcePath = Join-Path $OutputRoot $OutputName

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("# Generated from Jupyter notebook: $RelPath")
        $lines.Add('# Static scanner projection: code cells only; notebook was NOT executed.')
        $lines.Add('')

        $cellNumber = 0
        foreach ($cell in @($notebook.cells)) {
            $cellNumber++
            $cellType = if ($cell.PSObject.Properties['cell_type']) { [string]$cell.cell_type } else { '' }

            if ($cell.PSObject.Properties['outputs'] -and @($cell.outputs).Count -gt 0) {
                $findings.Add((New-NotebookFinding -RelPath $RelPath -Severity 'LOW' -CellNumber $cellNumber `
                    -Issue "Notebook cell $cellNumber has saved outputs (not analyzed as Python code)." `
                    -TestID 'NOTEBOOK-SAVED-OUTPUT'))
            }
            if ($cell.PSObject.Properties['attachments'] -and $cell.attachments) {
                $attachCount = @($cell.attachments.PSObject.Properties).Count
                if ($attachCount -gt 0) {
                    $findings.Add((New-NotebookFinding -RelPath $RelPath -Severity 'LOW' -CellNumber $cellNumber `
                        -Issue "Notebook cell $cellNumber has $attachCount attachment(s) (not analyzed as Python code)." `
                        -TestID 'NOTEBOOK-ATTACHMENT'))
                }
            }

            if ($cellType -ne 'code') { continue }

            $source = ''
            if ($cell.PSObject.Properties['source'] -and $null -ne $cell.source) {
                $source = if ($cell.source -is [array]) { (@($cell.source) -join '') } else { [string]$cell.source }
            }
            $lines.Add("# Cell $cellNumber")
            foreach ($line in ($source -split "`r?`n")) { $lines.Add($line) }
            $lines.Add('')
        }

        [IO.File]::WriteAllLines($sourcePath, $lines.ToArray(), (New-Object System.Text.UTF8Encoding($false)))
        Write-Log -Level INFO -Message "Notebook projection: $RelPath -> $(Split-Path $sourcePath -Leaf)"
        return @{ Success = $true; SourcePath = $sourcePath; Findings = $findings.ToArray() }

    } catch {
        $findings.Add((New-NotebookFinding -RelPath $RelPath -Severity 'HIGH' `
            -Issue "Notebook could not be parsed for code-cell analysis: $_" `
            -TestID 'NOTEBOOK-MALFORMED'))
        Write-Log -Level WARN -Message "Notebook parse error for $RelPath : $_"
        return @{ Success = $false; SourcePath = $null; Findings = $findings.ToArray() }
    }
}

function Test-IsNotebookUnit {
    param([PSCustomObject]$Unit)
    return ([IO.Path]::GetExtension($Unit.Name).ToLowerInvariant() -eq '.ipynb')
}
