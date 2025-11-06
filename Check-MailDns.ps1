<#
.SYNOPSIS
  Prüft die für E-Mail-Betrieb wichtigen DNS-Records (MX, SPF, DMARC, DKIM, SRV/443)
  für eine oder mehrere Domains über eure interne DNS-REST-API.

.DESCRIPTION
  Warum dieses Skript?
  - Bevor ihr DNSSEC/DMARC „hart“ dreht, wollt ihr sicher sein, dass die Mail-DNS-Basics stimmen.
  - Dieses Skript prüft automatisiert:
      MX (@-Domain)                          -> Mail-Routing
      SPF (TXT @-Domain)                     -> Versandautorisierung
      DMARC (TXT _dmarc.<domain>)            -> Richtlinie none/quarantine/reject
      DKIM (TXT/CNAME *_domainkey.*)         -> Signaturschlüssel oder Delegation
      SRV _autodiscover._tcp.<domain> :443   -> Outlook Autodiscover auf Port 443
  - Bewertet den Status (OK/WARN/FAIL), optional strenger mit -Strict.
  - Gibt ein maschinenlesbares JSON zurück + (optional) eine tabellarische Zusammenfassung.
  - Exitcodes: 0 OK | 1 WARN | 2 FAIL (ideal für CI/CD).

.PARAMETER ApiBase
  Basis-URL eurer DNS-API (ohne Slash am Ende), z. B.:
  https://noc-portal.itc.rwth-aachen.de/dns-admin/api/v1

.PARAMETER ApiToken
  API-Token (alternativ: Umgebungsvariable DNS_API_TOKEN). Basic-Auth-Token-String.

.PARAMETER Domains
  Eine oder mehrere FQDNs (z. B. "mustereinrichtung.rwth-aachen.de").

.PARAMETER OutputJson
  Pfad, unter dem der JSON-Report zusätzlich als Datei gespeichert wird (UTF-8).

.PARAMETER AltRoot
  Alternative Root für DKIM-Delegation (Default: rwth-aachen.de).
  Hintergrund: Manche DKIM-Keys liegen zentral unter *. _domainkey.rwth-aachen.de.

.PARAMETER IncludeDrafts
  Records ohne "status=deployed" ebenfalls berücksichtigen (Standard: nur deployed).

.PARAMETER VerboseZones
  Gibt ausführliche Zonendetails (ID, dnssec, status) aus (mit -Verbose sichtbar).

.PARAMETER DebugHttp
  Loggt jede HTTP-Anfrage (Body-first/QS-Fallback) als Verbose-Ausgabe.

.PARAMETER Strict
  Hebt „weiche“ Warnungen auf FAIL an:
   - SPF ohne „-all“ => FAIL (statt WARN)
   - DMARC mit „p=none“ => FAIL (statt WARN)

.PARAMETER Summary
  Druckt vor dem JSON eine kompakte Tabelle für Menschen/Logs.

.EXAMPLE
  $env:DNS_API_TOKEN="..."
  .\Check-MailDns.ps1 `
    -ApiBase "https://.../api/v1" `
    -Domains "mustereinrichtung.rwth-aachen.de" `
    -Summary -OutputJson ".\reports\maildns.json"

.EXAMPLE
  # Streng für CI/CD (blockend, wenn p=none oder SPF ohne -all):
  .\Check-MailDns.ps1 -ApiBase "https://.../api/v1" -Domains "a.de","b.de" -Strict -Summary

.NOTES
  - Kompatibel mit Windows PowerShell 5.1 und PowerShell 7+.
  - Datei als UTF-8 speichern. Konsole wird auf UTF-8 umgestellt; Konsolenstrings sind ASCII, um Anzeigeprobleme zu vermeiden.
  - Exitcodes: 0 OK | 1 WARN | 2 FAIL
#>

[CmdletBinding(PositionalBinding=$false)]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [ValidateScript({ $_ -match '^https?://.+' })]
  [string]$ApiBase,

  [Parameter()]
  [string]$ApiToken = $env:DNS_API_TOKEN,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string[]]$Domains,

  [Parameter()]
  [string]$OutputJson,

  [Parameter()]
  [string]$AltRoot = 'rwth-aachen.de',

  [switch]$IncludeDrafts,
  [switch]$VerboseZones,
  [switch]$DebugHttp,
  [switch]$Strict,
  [switch]$Summary
)

# --- UTF-8/Codepage: stabile Ausgabe, aber Konsolen-Strings bleiben ASCII -----
try { chcp 65001 | Out-Null } catch {}
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() } catch {}
# Hinweis: Manche Hosts ignorieren das. Darum vermeiden wir Umlaute in Write-Host-Strings.

# --- Grundsetup & Guards ------------------------------------------------------
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ApiToken)) {
  throw 'API-Token fehlt. Übergib -ApiToken oder setze DNS_API_TOKEN.'
}
$Headers = @{ 'Authorization' = "Basic $ApiToken" }
$ApiBase = $ApiBase.TrimEnd('/')

# --- Logging-Helfer (einheitlich, steuerbar) ---------------------------------
function Write-DebugHttp([string]$msg) { if ($DebugHttp) { Write-Verbose $msg } }
function Write-Info([string]$msg)     { Write-Verbose $msg }

# --- HTTP-Wrapper: Body-first (doc-konform), QS-Fallback ----------------------
function Invoke-ApiBody {
  param([Parameter(Mandatory=$true)][string]$Path, [hashtable]$Form)
  $uri = "$ApiBase/$Path"
  Write-DebugHttp "[HTTP] GET $uri  (Body)"
  Invoke-RestMethod -Method GET -Uri $uri -Headers $Headers -Body $Form -ErrorAction Stop
}
function Invoke-ApiQS {
  param([Parameter(Mandatory=$true)][string]$Path, [hashtable]$Form)
  $uri = "$ApiBase/$Path"
  $qs  = ''
  if ($Form) {
    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($kv in $Form.GetEnumerator()) {
      $val    = [string]$kv.Value
      # WICHTIG: '*' NICHT URL-encodieren, da Doku die Wildcard wörtlich erwartet
      $valEnc = [System.Uri]::EscapeDataString($val).Replace('%2A','*')
      $pairs.Add('{0}={1}' -f $kv.Key,$valEnc)
    }
    $qs = ($pairs -join '&')
  }
  $uriQS = if ($qs) { "$uri`?$qs" } else { $uri }
  Write-DebugHttp "[HTTP] GET $uriQS  (QS)"
  Invoke-RestMethod -Method GET -Uri $uriQS -Headers $Headers -ErrorAction Stop
}

# --- Preflight: prüft Token & Basis-Konnektivität -----------------------------
function Test-ApiConnectivity {
  try {
    $info = Invoke-ApiBody -Path 'get_api_token_info' -Form $null
    Write-Info ('[API] Token OK: {0}' -f $info.name)
  } catch {
    throw ('API-Check fehlgeschlagen. Pruefe -ApiBase ({0}) und Token. Fehler: {1}' -f $ApiBase, $_.Exception.Message)
  }
  try {
    [void](Invoke-ApiBody -Path 'list_zones' -Form @{ search='*' })
  } catch {
    Write-Warning ('Zonenliste nicht abrufbar: {0}' -f $_.Exception.Message)
  }
}
Test-ApiConnectivity

# --- Utilities: Suchmuster, Textbereinigung, FQDN usw. ------------------------
function Format-SearchPattern {
  <#
    Erzeugt ein Wildcard-Suchmuster: "abc" -> "*abc*".
    Wenn bereits Wildcards enthalten sind, wird der Text unverändert zurückgegeben.
  #>
  param([string]$InputText)
  if ([string]::IsNullOrWhiteSpace($InputText)) { return '*' }
  if ($InputText.Contains('*')) { return $InputText }
  '*{0}*' -f $InputText
}
function Remove-Comment {
  <#
    Entfernt Kommentare ab Semikolon (;) – aber NICHT innerhalb von Anführungszeichen.
    Hintergrund: TXT-Records enthalten oft Semikola in Werten; die sind Teil des Inhalts.
  #>
  param([string]$InputText)
  if ($null -eq $InputText) { return $InputText }
  $inQ = $false
  $sb  = New-Object System.Text.StringBuilder
  foreach ($ch in $InputText.ToCharArray()) {
    if ($ch -eq '"') { $inQ = -not $inQ; [void]$sb.Append($ch); continue }
    if (($ch -eq ';') -and -not $inQ) { break }
    [void]$sb.Append($ch)
  }
  $sb.ToString().Trim()
}
function Remove-TrailingDot {
  <#
    Entfernt den abschließenden Punkt eines FQDN ("example.com.") -> "example.com"
    (DNS-Notation erlaubt/erwartet oft einen finalen Punkt, der fürs Matching stören kann)
  #>
  param([string]$Fqdn)
  if ($null -eq $Fqdn) { return $Fqdn }
  $Fqdn.TrimEnd('.')
}
function ConvertTo-CleanArray {
  <#
    Sorgt dafür, dass wir ein "sauberes" Array ohne $null/'' zurückgeben.
    Wird später zusätzlich über den "unary comma" ,(...) IMMER als Array serialisiert.
  #>
  param($InputObject)
  @($InputObject) | Where-Object { $_ -ne $null -and $_ -ne '' }
}

# --- Zonen & Records aus der API ziehen (mit robusten Fallbacks) ---------------
function Get-Zones {
  <#
    Zieht Zonen aus der API. Probiert:
      1) Body mit search=<pattern>
      2) QueryString mit search=<pattern>
      3) jeweils mit "*" (breite Suche)
      4) ohne Parameter (voller Dump)
  #>
  param([string]$Search='*')
  $Search = Format-SearchPattern $Search

  try { $res = @( Invoke-ApiBody -Path 'list_zones' -Form @{ search=$Search } ) } catch { $res=@() }
  if ($res.Count -gt 0) { return $res }

  try { $res = @( Invoke-ApiQS   -Path 'list_zones' -Form @{ search=$Search } ) } catch { $res=@() }
  if ($res.Count -gt 0) { return $res }

  if ($Search -ne '*') {
    try { $res = @( Invoke-ApiBody -Path 'list_zones' -Form @{ search='*' } ) } catch { $res=@() }
    if ($res.Count -gt 0) { return $res }
    try { $res = @( Invoke-ApiQS   -Path 'list_zones' -Form @{ search='*' } ) } catch { $res=@() }
    if ($res.Count -gt 0) { return $res }
  }

  try { $res = @( Invoke-ApiBody -Path 'list_zones' -Form $null ) } catch { $res=@() }
  if ($res.Count -gt 0) { return $res }

  try { $res = @( Invoke-ApiQS   -Path 'list_zones' -Form $null ) } catch { $res=@() }
  $res
}

function Get-PrimaryZoneForFqdn {
  <#
    Findet die "beste" (längst-passende) Zone für eine FQDN.
    Beispiel: FQDN "mail.itc.rwth-aachen.de" → Zone "itc.rwth-aachen.de".
    Fallback: Testet auch nur die letzten zwei Labels (example.tld), falls nötig.
  #>
  param([Parameter(Mandatory=$true)][string]$Fqdn)
  $fq = $Fqdn.TrimEnd('.').ToLower()

  $cands = @( Get-Zones -Search $fq )
  if ($cands.Count -eq 0) {
    $parts = $fq.Split('.')
    if ($parts.Length -ge 2) {
      $base2 = ($parts[-2..-1] -join '.')
      $cands = @( Get-Zones -Search $base2 )
    }
  }
  if ($cands.Count -eq 0) { return $null }

  $best = $null; $bestLen = -1
  foreach ($z in $cands) {
    $zn = $z.zone_name; if ($null -eq $zn) { $zn = '' }
    $zn = $zn.TrimEnd('.').ToLower()
    if ($fq.EndsWith($zn) -and $zn.Length -gt $bestLen) {
      $best    = $z
      $bestLen = $zn.Length
    }
  }
  $best
}

function Find-Records {
  <#
    Sucht Records über die API. Optional wird die Suche auf eine Zone-ID eingeschränkt
    (performanter/gezielter). Standardmäßig werden nur "deployed" Records geliefert,
    außer -IncludeDrafts ist gesetzt.
  #>
  param([Parameter(Mandatory=$true)][string]$Search,[Nullable[int]]$ZoneId = $null)
  $form = @{ search = (Format-SearchPattern $Search) }
  if ($ZoneId) { $form.zone_id = [int]$ZoneId }

  try { $res = @( Invoke-ApiBody -Path 'list_records' -Form $form ) } catch { $res=@() }
  if ($res.Count -eq 0) {
    try { $res = @( Invoke-ApiQS   -Path 'list_records' -Form $form ) } catch { $res=@() }
  }

  $items = @($res)
  if (-not $IncludeDrafts) {
    $items = $items | Where-Object {
      ($_.PSObject.Properties.Name -contains 'status' -and $_.status -eq 'deployed') -or
      -not ($_.PSObject.Properties.Name -contains 'status')
    }
  }
  $items
}

# --- Regex-Parser für die Record-Formate (robust & kommentiert) ---------------
# Beispiel-Zeile (MX):
#   mustereinrichtung.rwth-aachen.de. IN MX 4422 mx1.rz.rwth-aachen.de.
$reMX     = [regex] '^\s*(?<name>\S+)\s+(?:(?<ttl>\d+)\s+)?IN\s+MX\s+(?<pref>\d+)\s+(?<target>\S+)'
# TXT-Erkennung (wir prüfen Inhalte separat auf v=spf1 / v=DMARC1)
$reTXT    = [regex] '\sIN\sTXT\s'
# SRV-Zeile (Port extrahieren, für 443-Check)
$reSRV    = [regex] '\sIN\sSRV\s+(?<prio>\d+)\s+(?<weight>\d+)\s+(?<port>\d+)\s+(?<target>\S+)'
# DMARC-Richtlinie p=
$reDMARCp = [regex] '(?i)\bp\s*=\s*(?<p>none|quarantine|reject)\b'
# SPF muss -all enthalten, sonst nur WARN (oder FAIL mit -Strict)
$reSPFAll = [regex] '(?i)\s-all\b'

# --- Einzelfunktions-Checks ---------------------------------------------------
function Test-MX {
  <# Sucht MX-Records, deren Name zur Domain passt. #>
  param([string]$Domain,[int]$ZoneId)
  $hits = @()
  foreach ($r in (Find-Records -Search $Domain -ZoneId $ZoneId)) {
    $line = Remove-Comment $r.content
    if ($reMX.IsMatch($line) -and $line -match "(^|\s)$([Regex]::Escape($Domain))(\.|\s)") {
      $m=$reMX.Match($line)
      $hits += [pscustomobject]@{
        record_id=$r.id
        name   =(Remove-TrailingDot $m.Groups['name'].Value)
        pref   =[int]$m.Groups['pref'].Value
        target =(Remove-TrailingDot $m.Groups['target'].Value)
        raw    =$line
      }
    }
  }
  $hits
}
function Test-SPF {
  <# Sucht TXT-Records mit v=spf1 an der @-Domain. #>
  param([string]$Domain,[int]$ZoneId)
  $hits = @()
  foreach ($r in (Find-Records -Search $Domain -ZoneId $ZoneId)) {
    $line = Remove-Comment $r.content
    if ($reTXT.IsMatch($line) -and $line -match '(?i)v=spf1') { $hits += $line }
  }
  $conc = ($hits -join ' ')
  @{
    present   = (@($hits).Count -gt 0)
    warnNoAll = (-not (@($hits).Count -eq 0) -and -not ($conc -match $reSPFAll))
    found     = @($hits)
  }
}
function Test-DMARC {
  <# Sucht TXT-Record v=DMARC1 unter _dmarc.<domain>; liest p=none/quarantine/reject aus. #>
  param([string]$Domain,[int]$ZoneId)
  $hits = @()
  foreach ($r in (Find-Records -Search ("_dmarc.$Domain") -ZoneId $ZoneId)) {
    $line = Remove-Comment $r.content
    if ($reTXT.IsMatch($line) -and $line -match '(?i)v=DMARC1') {
      $p = $null
      if ($reDMARCp.IsMatch($line)) { $p = $reDMARCp.Match($line).Groups['p'].Value.ToLower() }
      $hits += [pscustomobject]@{record_id=$r.id; policy=$p; raw=$line}
    }
  }
  $pols = @($hits | Where-Object { $_.policy } | ForEach-Object { $_.policy })
  @{
    present    = (@($hits).Count -gt 0)
    policyWarn = ($pols -and ($pols -contains 'none'))  # p=none -> WARN (oder FAIL mit -Strict)
    found      = @($hits | ForEach-Object { $_.raw })
  }
}
function Test-DKIM {
  <#
    Sucht DKIM unter *_domainkey.<domain> (TXT/CNAME, TXT enthält i. d. R. v=DKIM1/p=),
    zusätzlich optional unter *_domainkey.<AltRoot> (zentrale Delegation).
  #>
  param([string]$Domain,[int]$DomainZoneId,[string]$AltRoot)
  $hits = @()
  foreach ($r in (Find-Records -Search ("_domainkey.$Domain") -ZoneId $DomainZoneId)) {
    $line=Remove-Comment $r.content
    $isTxt   = ($line -match '_domainkey') -and ($line -match '\sIN\sTXT\s') -and ( ($line -match '(?i)v=DKIM1') -or ($line -match '\bp=') )
    $isCname = ($line -match '_domainkey') -and ($line -match '\sIN\sCNAME\s')
    if ($isTxt -or $isCname) { $hits += $line }
  }
  if (-not [string]::IsNullOrWhiteSpace($AltRoot)) {
    $alt = Get-PrimaryZoneForFqdn -Fqdn $AltRoot
    if ($alt) {
      foreach ($r in (Find-Records -Search ("_domainkey.$AltRoot") -ZoneId ([int]$alt.id))) {
        $line=Remove-Comment $r.content
        $isTxt   = ($line -match '_domainkey') -and ($line -match '\sIN\sTXT\s') -and ( ($line -match '(?i)v=DKIM1') -or ($line -match '\bp=') )
        $isCname = ($line -match '_domainkey') -and ($line -match '\sIN\sCNAME\s')
        if ($isTxt -or $isCname) { $hits += $line }
      }
    }
  }
  @{ present = (@($hits).Count -gt 0); found = @($hits) }
}
function Test-SRV443 {
  <# Sucht Autodiscover-SRV auf Port 443. #>
  param([string]$Domain,[int]$ZoneId)
  $hits = @()
  foreach ($r in (Find-Records -Search ("_autodiscover._tcp.$Domain") -ZoneId $ZoneId)) {
    $line=Remove-Comment $r.content
    if ($reSRV.IsMatch($line)) {
      $m=$reSRV.Match($line)
      $hits += [pscustomobject]@{
        record_id=$r.id
        port  =[int]$m.Groups['port'].Value
        target=(Remove-TrailingDot $m.Groups['target'].Value)
        raw   =$line
      }
    }
  }
  $present   = (@($hits).Count -gt 0)
  $wrongPort = $false
  if ($present) { $wrongPort = -not ($hits | Where-Object { $_.port -eq 443 }) }
  @{ present=$present; wrongPort=$wrongPort; found = @($hits | ForEach-Object { $_.raw }) }
}

# --- Hauptlauf: je Domain Zone finden -> Checks -> Bewertung -> Report --------
$domainReports = @()

foreach ($d0 in $Domains) {
  $d = $d0.Trim().TrimEnd('.')
  # ASCII, damit jede Konsole es sicher darstellt:
  Write-Host ('Pruefe {0} ...' -f $d) -ForegroundColor Cyan

  # 1) Zone bestimmen (beste Übereinstimmung)
  $zone = Get-PrimaryZoneForFqdn -Fqdn $d
  if ($VerboseZones) {
    if ($zone) { Write-Verbose ('Zone: {0} (#{1}) dnssec={2} status={3}' -f $zone.zone_name,$zone.id,$zone.dnssec,$zone.status) }
    else { Write-Warning 'Keine passende Zone gefunden.' }
  }

  # 2) Default-Struktur für Checks
  $mx   = @()
  $spf  = @{ present=$false; warnNoAll=$false; found=$null }
  $dmarc= @{ present=$false; policyWarn=$false; found=$null }
  $dkim = @{ present=$false; found=$null }
  $srv  = @{ present=$false; wrongPort=$false; found=$null }

  # 3) Checks ausführen (mit Zone → präziser; ohne Zone → best effort)
  if ($zone) {
    $zoneId = [int]$zone.id
    $mx     = Test-MX     -Domain $d -ZoneId $zoneId
    $spf    = Test-SPF    -Domain $d -ZoneId $zoneId
    $dmarc  = Test-DMARC  -Domain $d -ZoneId $zoneId
    $dkim   = Test-DKIM   -Domain $d -DomainZoneId $zoneId -AltRoot $AltRoot
    $srv    = Test-SRV443 -Domain $d -ZoneId $zoneId
  } else {
    Write-Warning '[Fallback] Suche ohne zone_id – Ergebnisse koennen unvollstaendig sein.'
    $mx = @( Find-Records -Search $d | ForEach-Object { $ln=Remove-Comment $_.content; if($ln -match '\sIN\sMX\s'){ [pscustomobject]@{ raw=$ln } } } )
    $sHits = @( Find-Records -Search $d | ForEach-Object { $ln=Remove-Comment $_.content; if($ln -match '\sIN\sTXT\s' -and $ln -match '(?i)v=spf1'){ $ln } } )
    if ($sHits.Count -gt 0) { $spf.present=$true; $spf.found=$sHits; $spf.warnNoAll = -not (($sHits -join ' ') -match $reSPFAll) }
    $dmHits = @( Find-Records -Search ("_dmarc.$d") | ForEach-Object { $ln=Remove-Comment $_.content; if($ln -match '\sIN\sTXT\s' -and $ln -match '(?i)v=DMARC1'){ $ln } } )
    $dmarc.present=($dmHits.Count -gt 0); $dmarc.found=$dmHits; $dmarc.policyWarn = (($dmHits -join ' ') -match '(?i)\bp\s*=\s*none\b')
    $dkHits = @( (Find-Records -Search ("_domainkey.$d")) + (Find-Records -Search ("_domainkey.$AltRoot")) | ForEach-Object { $ln=Remove-Comment $_.content; if($ln -match '_domainkey' -and ( ($ln -match '\sIN\sTXT\s' -and ($ln -match '(?i)v=DKIM1' -or $ln -match '\bp=')) -or ($ln -match '\sIN\sCNAME\s') )){ $ln } } )
    if ($dkHits.Count -gt 0){ $dkim.present=$true; $dkim.found=$dkHits }
    $srvHits = @( Find-Records -Search ("_autodiscover._tcp.$d") | ForEach-Object { $ln=Remove-Comment $_.content; if($ln -match '\sIN\sSRV\s+\d+\s+\d+\s+443\s+\S+'){ $ln } } )
    if ($srvHits.Count -gt 0){ $srv.present=$true; $srv.found=$srvHits }
  }

  # 4) Bewertung (OK / WARN / FAIL)
  $fail = @()
  $warn = @()
  if (-not @($mx).Count) { $fail += 'mx' }
  if (-not $spf.present) { $fail += 'spf' } elseif ($spf.warnNoAll) { $warn += 'spf:no -all' }
  if (-not $dmarc.present) { $fail += 'dmarc' } elseif ($dmarc.policyWarn) { $warn += 'dmarc:p=none' }
  if (-not $dkim.present) { $fail += 'dkim' }
  if (-not $srv.present)  { $fail += 'srv' } elseif ($srv.wrongPort) { $fail += 'srv:port!=443' }

  # Strenger Modus: manche WARNs werden zu FAIL
  if ($Strict) {
    if ($warn -contains 'spf:no -all')  { $fail += 'spf:no -all';  $warn = $warn | Where-Object { $_ -ne 'spf:no -all' } }
    if ($warn -contains 'dmarc:p=none') { $fail += 'dmarc:p=none'; $warn = $warn | Where-Object { $_ -ne 'dmarc:p=none' } }
  }

  $status = 'OK'
  if     ($fail.Count -gt 0) { $status = 'FAIL: ' + ($fail -join ', ') }
  elseif ($warn.Count -gt 0) { $status = 'WARN: ' + ($warn -join ', ') }

  # 5) Reportobjekt (JSON-stabil: found IMMER als Array dank unary comma)
  $domainReports += [pscustomobject]@{
    domain = $d
    status = $status
    checks = [pscustomobject]@{
      mx     = @{ present = (@($mx).Count -gt 0);                     found = ,(ConvertTo-CleanArray ($mx | ForEach-Object { $_.raw })) }
      spf    = @{ present = $spf.present;  warnNoAll = $spf.warnNoAll; found = ,(ConvertTo-CleanArray $spf.found) }
      dmarc  = @{ present = $dmarc.present; policyWarn = $dmarc.policyWarn; found = ,(ConvertTo-CleanArray $dmarc.found) }
      dkim   = @{ present = $dkim.present;                              found = ,(ConvertTo-CleanArray $dkim.found) }
      srv443 = @{ present = $srv.present;   wrongPort = $srv.wrongPort;  found = ,(ConvertTo-CleanArray $srv.found) }
    }
  }
}

# --- Optionale Menschentabelle (für Präsentation/Logs) ------------------------
if ($Summary) {
  Write-Host "`n=== Zusammenfassung ===`n" -ForegroundColor Cyan
  $rows = foreach ($r in $domainReports) {
    [pscustomobject]@{
      Domain = $r.domain
      Status = $r.status
      MX     = if ($r.checks.mx.present) { 'OK' } else { '--' }
      SPF    = if ($r.checks.spf.present) {
                 if ($r.checks.spf.warnNoAll -and -not $Strict) { 'WARN' }
                 elseif ($r.checks.spf.warnNoAll -and $Strict)  { 'FAIL' }
                 else { 'OK' }
               } else { '--' }
      DMARC  = if ($r.checks.dmarc.present) {
                 if ($r.checks.dmarc.policyWarn -and -not $Strict) { 'WARN' }
                 elseif ($r.checks.dmarc.policyWarn -and $Strict)  { 'FAIL' }
                 else { 'OK' }
               } else { '--' }
      DKIM   = if ($r.checks.dkim.present) { 'OK' } else { '--' }
      SRV443 = if ($r.checks.srv443.present) {
                 if ($r.checks.srv443.wrongPort) { 'FAIL' } else { 'OK' }
               } else { '--' }
    }
  }
  $rows | Format-Table -AutoSize
  Write-Host ''
}

# --- JSON-Ausgabe + Datei (UTF-8) ---------------------------------------------
$report = [pscustomobject]@{
  timestamp = (Get-Date).ToUniversalTime().ToString('o')
  results   = $domainReports
}
$reportJson = $report | ConvertTo-Json -Depth 8
Write-Output $reportJson

if ($OutputJson -and $OutputJson.Trim()) {
  $dir = Split-Path -Parent $OutputJson
  if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }
  Set-Content -Path $OutputJson -Value $reportJson -Encoding UTF8
  Write-Verbose ('Report gespeichert unter {0}' -f $OutputJson)
}

# --- Exitcode für CI/CD -------------------------------------------------------
$hasFail = $domainReports | Where-Object { $_.status -like 'FAIL*' }
$hasWarn = $domainReports | Where-Object { $_.status -like 'WARN*' }

if ($hasFail) { exit 2 }
elseif ($hasWarn) { exit 1 }
else { exit 0 }
