<#


01-03  Was macht das Skript?
       Es prueft Mail-DNS-Eintraege (MX, SPF, DMARC, DKIM, Autodiscover) fuer Domains.

04-10  Grober Ablauf:
       (1) Parameter und API pruefen
       (2) Domainliste sammeln (manuell oder per Suche)
       (3) DNS-Records abrufen
       (4) Ergebnisse ausgeben (JSON, optional Tabelle)

11-18  Wofuer stehen die Checks?
       MX     = Mail-Routing
       SPF    = Wer darf Mails senden?
       DMARC  = Policy (none/quarantine/reject)
       DKIM   = Signaturschluessel oder Delegation
       SRV443 = Outlook-Autodiscover auf Port 443

19-23  Diese Datei enthaelt viele Hilfsfunktionen, damit die API-Abfragen stabil sind
       (Fallbacks, Caches, Debug-Ausgaben).

24-58  Parameter (Eingaben) kurz erklaert:
       ApiBase      = Basis-URL der DNS-API (ohne Slash am Ende)
       ApiToken     = Basic-Auth-Token (oder Umgebungsvariable DNS_API_TOKEN)
       Domains      = Liste der zu pruefenden Domains
       DomainSearch = Suchmuster fuer list_zones (Wildcards moeglich)
       OutputJson   = Pfad, wohin der JSON-Report geschrieben wird
       AltRoot      = Alternative Root fuer DKIM-Delegation
       IncludeDrafts= auch Records mit Status "draft" einbeziehen
       VerboseZones = Zusatzinfos zur Zone anzeigen
       DebugHttp    = jede HTTP-Anfrage sichtbar machen
       VerboseOutput= ausfuehrliche Fortschrittsmeldungen
       Strict       = SPF ohne "-all" und DMARC "p=none" als Fehler werten
       Summary      = vor JSON eine Tabelle anzeigen
       SmtpServer   = SMTP-Server fuer Fehlerberichte
       SmtpPort     = SMTP-Port (Standard 25)
       SmtpFrom     = Absenderadresse fuer Fehlerberichte
       SmtpTo       = Empfaengeradresse(n) fuer Fehlerberichte
       SmtpUser     = optionaler SMTP-Benutzer
       SmtpPassword = optionales SMTP-Passwort
       SmtpUseSsl   = SMTP mit SSL/TLS verwenden
       SmtpSubject  = Betreff fuer Fehlerberichte

60-70  Beispiele: zeigen, wie man das Skript aufruft.

71-76  Hinweise:
       - PowerShell 5.1 und 7+ werden unterstuetzt.
       - UTF-8-Speicherung empfohlen.
       - Exitcodes: 0=OK, 1=Warnung, 2=Fehler.
       - Ohne Domains werden automatisch Dateien gesucht.
#>


param(
  [string]$ApiBase,
  [string]$ApiToken = $env:DNS_API_TOKEN,
  [object[]]$Domains = @(),
  [object[]]$DomainSearch = @(),
  [string]$OutputJson,
  [string]$AltRoot = 'rwth-aachen.de',
  [switch]$IncludeDrafts,
  [switch]$VerboseZones,
  [switch]$DebugHttp,
  [switch]$Strict,
  [switch]$Summary,
  [Alias('Verbose')][switch]$VerboseOutput,
  [string]$SmtpServer,
  [int]$SmtpPort = 25,
  [string]$SmtpFrom,
  [string[]]$SmtpTo,
  [string]$SmtpUser,
  [string]$SmtpPassword,
  [switch]$SmtpUseSsl,
  [string]$SmtpSubject = 'Mail-DNS-Check Fehlerbericht'
)

if ([string]::IsNullOrWhiteSpace($ApiBase) -or ($ApiBase -notmatch '^https?://.+')) {
  throw 'Parameter -ApiBase erwartet eine vollstaendige https://- oder http://-URL.'
}

# ============================================================================
# SECTION 1 - Konsoleneinstellungen und Grundkonfiguration
#   - $ShowVerbose merkt sich, ob wir detaillierte Ausgaben zeigen sollen.
#   - chcp 65001 und OutputEncoding stellen UTF-8 ein (Umlaute korrekt).
#   - ErrorActionPreference = Stop -> Fehler stoppen sofort das Skript.
#   - Fehlt das Token, wird abgebrochen (ohne Auth keine API).
#   - $Headers enthaelt den Authorization-Header.
#   - $ApiBase wird normalisiert (kein Slash am Ende).
#   - $Domains/$DomainSearch werden auf leere Arrays gesetzt, falls $null.
#   - Caches fuer spaetere Abfragen werden vorbereitet.
# ============================================================================
$ShowVerbose = $VerboseOutput.IsPresent

try { chcp 65001 | Out-Null } catch {}
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() } catch {}

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ApiToken)) {
  throw 'API-Token fehlt. Uebergib -ApiToken oder setze DNS_API_TOKEN.'
}
$Headers = @{ 'Authorization' = "Basic $ApiToken" }
$ApiBase = $ApiBase.TrimEnd('/')
if ($null -eq $Domains) { $Domains = @() }
if ($null -eq $DomainSearch) { $DomainSearch = @() }
if (-not $script:AltRootZoneCache) { $script:AltRootZoneCache = @{} }
if (-not $script:RecordCache)    { $script:RecordCache    = @{} }

# ============================================================================
# SECTION 5A - Default-Domain-Fallback
#   - Wir suchen nach Dateien wie maildomains.txt oder smallmaildomains.txt.
#   - Wir pruefen Script-Ordner, aktuelles Verzeichnis und deren Eltern.
#   - Wird eine Datei gefunden, laden wir sie als Domainliste.
#   - Kommentare und Leerzeilen werden entfernt.
# ============================================================================
function Get-FallbackDomainFile {
  $locations = [System.Collections.Generic.List[string]]::new()

  $scriptDir = $null
  if ($PSCommandPath) {
    $scriptDir = Split-Path -Parent $PSCommandPath
  } elseif ($PSScriptRoot) {
    $scriptDir = $PSScriptRoot
  } elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
  }

  $current = (Get-Location).Path

  foreach ($dir in @($scriptDir, $current) | Where-Object { $_ }) {
    $locations.Add($dir) | Out-Null

    $parent = $dir
    for ($i = 0; $i -lt 5; $i++) {
      $parent = Split-Path -Parent $parent
      if (-not $parent) { break }
      $locations.Add($parent) | Out-Null
    }
  }

  $names = @('maildomains.txt','smallmaildomains.txt')
  $seenPaths  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  foreach ($dir in $locations | Where-Object { $_ }) {
    foreach ($name in $names) {
      $candidate = Join-Path $dir $name
      if ($seenPaths.Add($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return $candidate
      }
    }
  }

  return $null
}

function Import-FallbackDomains {
  $file = Get-FallbackDomainFile
  if (-not $file) { return [pscustomobject]@{ Domains = @(); Source = $null } }

  try {
    $content = Get-Content -LiteralPath $file -ErrorAction Stop
  } catch {
    Write-Warning ('Fallback-Datei "{0}" konnte nicht gelesen werden: {1}' -f $file, $_.Exception.Message)
    return [pscustomobject]@{ Domains = @(); Source = $file }
  }

  $domains = @(
    $content |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -and -not $_.StartsWith('#') }
  )

  [pscustomobject]@{ Domains = $domains; Source = $file }
}

# ============================================================================
# SECTION 2 - Logging-Helfer
#   - Write-DebugHttp zeigt HTTP-Aufrufe in Farbe (nur bei Debug/Verbose).
#   - Write-Info zeigt allgemeine Infos nur im Verbose-Modus.
# ============================================================================
function Write-DebugHttp {
  param([string]$Message)
  if ($DebugHttp) {
    Write-Host $Message -ForegroundColor DarkYellow
  } elseif ($ShowVerbose) {
    Write-Host $Message -ForegroundColor DarkGray
  }
}
function Write-Info {
  param([string]$Message)
  if ($ShowVerbose) {
    Write-Host $Message -ForegroundColor DarkGray
  }
}

function Send-ErrorReport {
  param(
    [Parameter(Mandatory=$true)][string]$ReportJson,
    [Parameter(Mandatory=$true)][object[]]$DomainReports,
    [string]$ReportPath,
    [string]$SummaryText
  )

  if (-not $SmtpServer -or -not $SmtpFrom -or -not $SmtpTo -or $SmtpTo.Count -eq 0) {
    Write-Info 'SMTP-Fehlerbericht uebersprungen (SmtpServer/SmtpFrom/SmtpTo fehlen).'
    return
  }

  $failCount = ($DomainReports | Where-Object { $_.status -like 'FAIL*' }).Count
  $warnCount = ($DomainReports | Where-Object { $_.status -like 'WARN*' }).Count
  $subjectValue = if ($SmtpSubject -and $SmtpSubject.Trim()) { $SmtpSubject } else { 'Mail-DNS-Check Fehlerbericht' }

  $encodedReport = [System.Net.WebUtility]::HtmlEncode($ReportJson)
  $summaryBlock = if ($SummaryText -and $SummaryText.Trim()) {
@"
<h3 style="margin-bottom: 6px;">Zusammenfassung</h3>
<pre style="background: #f7f7f7; padding: 12px; border-radius: 6px; font-family: Consolas, Monaco, 'Courier New', monospace; white-space: pre; margin: 0 0 12px 0;">$SummaryText</pre>
"@
  } else { '' }

  $body = @"
<html>
  <body style="font-family: Arial, sans-serif; color: #222;">
    <p style="margin: 0 0 12px 0;">
      <strong>Mail-DNS-Check: Fehler erkannt.</strong><br/>
      Zeitpunkt (UTC): $((Get-Date).ToUniversalTime().ToString('o'))<br/>
      Domains: $($DomainReports.Count)<br/>
      Fehler: $failCount<br/>
      Warnungen: $warnCount
    </p>
    $summaryBlock
    <h3 style="margin-bottom: 6px;">Report (JSON)</h3>
    <pre style="background: #f7f7f7; padding: 12px; border-radius: 6px; font-family: Consolas, Monaco, 'Courier New', monospace;">$encodedReport</pre>
  </body>
</html>
"@

  $mailParams = @{
    SmtpServer = $SmtpServer
    Port       = $SmtpPort
    From       = $SmtpFrom
    To         = ($SmtpTo -join ',')
    Subject    = $subjectValue
    Body       = $body
    BodyAsHtml = $true
    ErrorAction= 'Stop'
  }

  if ($SmtpUseSsl) {
    $mailParams.UseSsl = $true
  }

  if ($SmtpUser -and $SmtpPassword) {
    $securePassword = ConvertTo-SecureString $SmtpPassword -AsPlainText -Force
    $mailParams.Credential = [pscredential]::new($SmtpUser, $securePassword)
  }

  if ($ReportPath -and (Test-Path -LiteralPath $ReportPath)) {
    $mailParams.Attachments = $ReportPath
  }

  try {
    Send-MailMessage @mailParams
    Write-Info 'Fehlerbericht per SMTP versendet.'
  } catch {
    Write-Warning ('SMTP-Fehlerbericht konnte nicht gesendet werden: {0}' -f $_.Exception.Message)
  }
}

# ============================================================================
# SECTION 3 - HTTP-Hilfsfunktionen
#   - Invoke-ApiGet baut eine GET-Anfrage (entweder Body oder Querystring).
#   - Invoke-ApiGetBoth probiert beide Varianten und sammelt Ergebnisse.
#   - Invoke-ApiGetAll gibt immer ein Array zurueck (auch bei Fehler -> leer).
#   - Test-ApiConnectivity prueft Token und list_zones zur API-Verbindung.
# ============================================================================
function Invoke-ApiGet {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [hashtable]$Form,
    [ValidateSet('Body','QueryString')][string]$Mode = 'Body'
  )

  $uri = "$ApiBase/$Path"
  switch ($Mode) {
    'Body' {
      Write-DebugHttp "[HTTP] GET $uri  (Body)"
      return Invoke-RestMethod -Method GET -Uri $uri -Headers $Headers -Body $Form -ErrorAction Stop
    }
    'QueryString' {
      $qs = ''
      if ($Form) {
        $pairs = foreach ($kv in $Form.GetEnumerator()) {
          $val = [string]$kv.Value
          $valEnc = [System.Uri]::EscapeDataString($val).Replace('%2A','*')
          '{0}={1}' -f $kv.Key,$valEnc
        }
        $qs = ($pairs -join '&')
      }
      $uriQS = if ($qs) { "$uri`?$qs" } else { $uri }
      Write-DebugHttp "[HTTP] GET $uriQS  (QS)"
      return Invoke-RestMethod -Method GET -Uri $uriQS -Headers $Headers -ErrorAction Stop
    }
  }
}

function Invoke-ApiGetBoth {
  param([Parameter(Mandatory=$true)][string]$Path, [hashtable]$Form)

  $results = @()
  $errors  = @()
  foreach ($mode in @('Body','QueryString')) {
    try {
      $results += @(Invoke-ApiGet -Path $Path -Form $Form -Mode $mode)
    } catch {
      $errors += $_
    }
  }

  if ($results.Count -eq 0 -and $errors.Count -gt 0) {
    throw $errors[-1]
  }

  $results
}

function Invoke-ApiGetAll {
  param([Parameter(Mandatory=$true)][string]$Path, [hashtable]$Form)
  try { @(Invoke-ApiGetBoth -Path $Path -Form $Form) } catch { @() }
}

function Test-ApiConnectivity {
  try {
    $info = Invoke-ApiGet -Path 'get_api_token_info' -Form $null
    Write-Info ('[API] Token OK: {0}' -f $info.name)
  } catch {
    throw ('API-Check fehlgeschlagen. Pruefe -ApiBase ({0}) und Token. Fehler: {1}' -f $ApiBase, $_.Exception.Message)
  }
  try {
    [void](Invoke-ApiGet -Path 'list_zones' -Form @{ search='*' })
  } catch {
    Write-Warning ('Zonenliste nicht abrufbar: {0}' -f $_.Exception.Message)
  }
}
Test-ApiConnectivity

# ============================================================================
# SECTION 5 - Utility-Funktionen fuer Textaufbereitung
#   - Format-SearchPattern macht aus "abc" -> "*abc*" (falls kein Wildcard).
#   - Remove-Comment entfernt Kommentare nach ';' (ausser in Anfuehrungszeichen).
#   - Remove-TrailingDot entfernt den Punkt am Ende einer Domain.
#   - ConvertTo-CleanArray entfernt Nulls/Leerstrings/Duplikate.
#   - Expand-InputCollection macht aus beliebigen Listen ein String-Array.
# ============================================================================
function Format-SearchPattern {
  <# "abc" -> "*abc*"; bereits vorhandene Wildcards bleiben erhalten. #>
  param([string]$InputText)
  if ([string]::IsNullOrWhiteSpace($InputText)) { return '*' }
  if ($InputText.Contains('*')) { return $InputText }
  '*{0}*' -f $InputText
}
function Remove-Comment {
  <# Schneidet Kommentare (;) ausserhalb von Anfuehrungszeichen ab. #>
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
  <# DNS-Notation erlaubt einen Punkt am Ende (example.com.). Wir entfernen ihn. #>
  param([string]$Fqdn)
  if ($null -eq $Fqdn) { return $Fqdn }
  $Fqdn.TrimEnd('.')
}
function ConvertTo-CleanArray {
  <# Stellt sicher, dass JSON-Arrays keine $null oder Leerstrings oder Duplikate enthalten. #>
  param($InputObject)

  $clean = @($InputObject) | Where-Object { $_ -ne $null -and $_ -ne '' }
  if ($clean.Count -le 1) { return $clean }

  $result = [System.Collections.Generic.List[object]]::new()
  $seenStrings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

  foreach ($item in $clean) {
    if ($item -is [string]) {
      if ($seenStrings.Add($item)) { $result.Add($item) | Out-Null }
    } else {
      $result.Add($item) | Out-Null
    }
  }

  $result.ToArray()
}

function Expand-InputCollection {
  <# Wandelt beliebige Eingabeobjekte (Strings, Arrays, Listen) in ein String-Array um. #>
  param([object[]]$Items)

  if ($null -eq $Items) { return @() }

  $result = [System.Collections.Generic.List[string]]::new()
  foreach ($item in $Items) {
    if ($null -eq $item) { continue }

    if ($item -is [string]) {
      $result.Add($item) | Out-Null
      continue
    }

    if ($item -is [System.Collections.IEnumerable] -and -not ($item -is [string])) {
      foreach ($subItem in $item) {
        if ($null -eq $subItem) { continue }
        $result.Add([string]$subItem) | Out-Null
      }
      continue
    }

    $result.Add([string]$item) | Out-Null
  }

  $result.ToArray()
}

# ============================================================================
# SECTION 6 - Zonen- und Recordabfragen
#   - Get-Zones fragt Zonen ab und nutzt mehrere Suchmuster + Cache.
#   - Get-PrimaryZoneForFqdn sucht die "beste" Zone (laengster Suffix-Match).
#   - Find-Records sucht Records, filtert Drafts und entfernt Duplikate.
#   - Get-RecordSearchTerms erzeugt Suchbegriffe (z.B. '@' oder relative Namen).
# ============================================================================
function Get-Zones {
  param([string]$Search='*')

  if (-not $script:ZoneCache) { $script:ZoneCache = @{} }

  $cacheKey = if ([string]::IsNullOrWhiteSpace($Search)) { '*' } else { $Search }
  if ($script:ZoneCache.ContainsKey($cacheKey)) {
    return $script:ZoneCache[$cacheKey]
  }

  $candidates = [System.Collections.Generic.List[string]]::new()
  if ([string]::IsNullOrWhiteSpace($Search)) {
    $candidates.Add('*') | Out-Null
  } else {
    $clean = $Search.Trim()
    $candidates.Add($clean) | Out-Null
    if (-not $clean.Contains('*')) {
      $candidates.Add("*$clean*") | Out-Null
      $candidates.Add("$clean*")  | Out-Null
      $candidates.Add("*$clean")  | Out-Null
    }
  }

  $finalList = $candidates | Where-Object { $_ } | Select-Object -Unique

  $results = @()
  foreach ($pattern in $finalList) {
    $form = if ($pattern -eq '*') { @{ search='*' } } else { @{ search=$pattern } }
    $results += Invoke-ApiGetAll -Path 'list_zones' -Form $form
  }

  if (-not $results) {
    if (-not ($finalList | Where-Object { $_ -eq '*' })) {
      $results += Invoke-ApiGetAll -Path 'list_zones' -Form @{ search='*' }
    }
    $results += Invoke-ApiGetAll -Path 'list_zones' -Form $null
  }

  $unique = @()
  $seen   = @{}
  foreach ($entry in $results) {
    $key = if ($entry.PSObject.Properties.Name -contains 'id') { "id:$($entry.id)" } else { "name:$($entry.zone_name)" }
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $unique += $entry
    }
  }

  $script:ZoneCache[$cacheKey] = $unique
  $unique
}

function Get-PrimaryZoneForFqdn {
  param([Parameter(Mandatory=$true)][string]$Fqdn)
  $fq = $Fqdn.TrimEnd('.').ToLower()

  $parts = $fq.Split('.')
  $searchOrder = [System.Collections.Generic.List[string]]::new()
  for ($i = 0; $i -lt $parts.Length; $i++) {
    $suffix = ($parts[$i..($parts.Length-1)] -join '.')
    if (-not [string]::IsNullOrWhiteSpace($suffix)) {
      $searchOrder.Add($suffix) | Out-Null
    }
  }
  if (-not $searchOrder.Contains('*')) { $searchOrder.Add('*') | Out-Null }

  $zoneCandidates = @()
  foreach ($pattern in ($searchOrder | Select-Object -Unique)) {
    $zoneCandidates += @( Get-Zones -Search $pattern )
  }
  if ($zoneCandidates.Count -eq 0) { return $null }

  $best = $null; $bestLen = -1
  foreach ($z in $zoneCandidates) {
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
  param(
    [Parameter(Mandatory=$true)][object]$Search,
    [Nullable[int]]$ZoneId = $null
  )

  $searchTerms = Expand-InputCollection -Items @($Search)
  $searchTerms = $searchTerms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
  if ($searchTerms.Count -eq 0) { return @() }

  $zonePart  = if ($ZoneId) { "zone:$ZoneId" } else { 'zone:null' }
  $draftPart = if ($IncludeDrafts) { 'drafts:include' } else { 'drafts:exclude' }
  $termsPart = 'terms:' + (($searchTerms | Sort-Object) -join '|')
  $cacheKey  = '{0}||{1}||{2}' -f $zonePart, $draftPart, $termsPart

  if ($script:RecordCache.ContainsKey($cacheKey)) {
    return $script:RecordCache[$cacheKey]
  }

  $collected = @()
  foreach ($term in $searchTerms) {
    $form = @{ search = (Format-SearchPattern $term) }
    if ($ZoneId) { $form.zone_id = [int]$ZoneId }

    $collected += Invoke-ApiGetAll -Path 'list_records' -Form $form
  }

  if (-not $collected) { return @() }

  if (-not $IncludeDrafts) {
    $collected = $collected | Where-Object {
      ($_.PSObject.Properties.Name -contains 'status' -and $_.status -eq 'deployed') -or
      -not ($_.PSObject.Properties.Name -contains 'status')
    }
  }

  $deduped = @()
  $seen = @{}
  foreach ($item in $collected) {
    $identifier = if ($item.PSObject.Properties.Name -contains 'id' -and $item.id) {
      "id:$($item.id)"
    } elseif ($item.PSObject.Properties.Name -contains 'name') {
      "name:$($item.name)|content:$($item.content)"
    } else {
      "content:$($item.content)"
    }
    if (-not $seen.ContainsKey($identifier)) {
      $seen[$identifier] = $true
      $deduped += $item
    }
  }

  $script:RecordCache[$cacheKey] = $deduped
  $deduped
}

function Get-RecordSearchTerms {
  param(
    [string]$Domain,
    $Zone
  )

  $terms = [System.Collections.Generic.List[string]]::new()
  $canonical = $Domain.Trim().TrimEnd('.')
  if ($canonical) { $terms.Add($canonical) | Out-Null }

  if ($Zone -and ($Zone.PSObject.Properties.Name -contains 'zone_name')) {
    $zoneName = ($Zone.zone_name -as [string])
    $zoneName = (Remove-TrailingDot $zoneName)
    if ($zoneName) {
      if ($canonical.Equals($zoneName, [System.StringComparison]::OrdinalIgnoreCase)) {
        $terms.Add('@') | Out-Null
      } elseif ($canonical.ToLower().EndsWith('.' + $zoneName.ToLower())) {
        $relative = $canonical.Substring(0, $canonical.Length - $zoneName.Length - 1)
        if (-not [string]::IsNullOrWhiteSpace($relative)) {
          $terms.Add($relative) | Out-Null
        }
      }
    }
  }

  $terms | Select-Object -Unique
}

# ============================================================================
# SECTION 7 - Regexe und Einzelpruefungen
#   - Regexe definieren, wie wir MX/TXT/SRV/DMARC/SPF erkennen.
#   - Test-MX sucht MX-Records und liest Preference + Ziel aus.
#   - Test-SPF findet v=spf1-Records und prueft "-all".
#   - Test-DMARC findet _dmarc-Records und liest die Policy.
#   - Test-DKIM sucht _domainkey-Records (TXT oder CNAME).
#   - Test-SRV443 prueft Autodiscover auf Port 443.
# ============================================================================
$reMX     = [regex] '^\s*(?<name>\S+)\s+(?:(?<ttl>\d+)\s+)?IN\s+MX\s+(?<pref>\d+)\s+(?<target>\S+)'
$reTXT    = [regex] '\sIN\sTXT\s'
$reSRV    = [regex] '\sIN\sSRV\s+(?<prio>\d+)\s+(?<weight>\d+)\s+(?<port>\d+)\s+(?<target>\S+)'
$reDMARCp = [regex] '(?i)\bp\s*=\s*(?<p>none|quarantine|reject)\b'
$reSPFAll = [regex] '(?i)\s-all\b'

function Test-MX {
  param([string]$Domain,[Nullable[int]]$ZoneId,[string[]]$SearchTerms)
  $hits = @()
  foreach ($r in (Find-Records -Search $SearchTerms -ZoneId $ZoneId)) {
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
  param([string]$Domain,[Nullable[int]]$ZoneId,[string[]]$SearchTerms)
  $hits = @()
  foreach ($r in (Find-Records -Search $SearchTerms -ZoneId $ZoneId)) {
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
  param([string]$Domain,[Nullable[int]]$ZoneId,[string[]]$SearchTerms)
  $hits = @()
  foreach ($r in (Find-Records -Search ($SearchTerms | ForEach-Object { "_dmarc.$_" }) -ZoneId $ZoneId)) {
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
    policyWarn = ($pols -and ($pols -contains 'none'))
    found      = @($hits | ForEach-Object { $_.raw })
  }
}
function Test-DKIM {
  param([string]$Domain,[Nullable[int]]$DomainZoneId,[string]$AltRoot,[string[]]$SearchTerms)

  $rawHits = [System.Collections.Generic.List[string]]::new()

  $dkimSearch = @()
  $dkimSearch += ($SearchTerms | ForEach-Object { "_domainkey.$_" })
  $dkimSearch = $dkimSearch | Where-Object { $_ } | Select-Object -Unique

  if ($dkimSearch.Count -gt 0) {
    foreach ($r in (Find-Records -Search $dkimSearch -ZoneId $DomainZoneId)) {
      $line = Remove-Comment $r.content
      if (-not $line) { continue }
      $isTxt   = ($line -match '_domainkey') -and ($line -match '\sIN\sTXT\s') -and ( ($line -match '(?i)v=DKIM1') -or ($line -match '\bp=') )
      $isCname = ($line -match '_domainkey') -and ($line -match '\sIN\sCNAME\s')
      if ($isTxt -or $isCname) { $rawHits.Add($line) | Out-Null }
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($AltRoot)) {
    $altKey = (Remove-TrailingDot $AltRoot).ToLower()
    if (-not $script:AltRootZoneCache.ContainsKey($altKey)) {
      $script:AltRootZoneCache[$altKey] = Get-PrimaryZoneForFqdn -Fqdn $AltRoot
    }
    $altZone   = $script:AltRootZoneCache[$altKey]
    $altZoneId = $null
    if ($altZone -and ($altZone.PSObject.Properties.Name -contains 'id') -and $altZone.id) {
      $altZoneId = [int]$altZone.id
    }
    foreach ($r in (Find-Records -Search @("_domainkey.$AltRoot") -ZoneId $altZoneId)) {
      $line = Remove-Comment $r.content
      if (-not $line) { continue }
      $isTxt   = ($line -match '_domainkey') -and ($line -match '\sIN\sTXT\s') -and ( ($line -match '(?i)v=DKIM1') -or ($line -match '\bp=') )
      $isCname = ($line -match '_domainkey') -and ($line -match '\sIN\sCNAME\s')
      if ($isTxt -or $isCname) { $rawHits.Add($line) | Out-Null }
    }
  }

  $hits = $rawHits | Select-Object -Unique
  @{ present = ($hits.Count -gt 0); found = @($hits) }
}
function Test-SRV443 {
  param([string]$Domain,[Nullable[int]]$ZoneId,[string[]]$SearchTerms)
  $hits = @()
  foreach ($r in (Find-Records -Search ($SearchTerms | ForEach-Object { "_autodiscover._tcp.$_" }) -ZoneId $ZoneId)) {
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
  if ($present) {
    $wrongPort = -not ($hits | Where-Object { $_.port -eq 443 } | Select-Object -First 1)
  }
  @{ present=$present; wrongPort=$wrongPort; found = @($hits | ForEach-Object { $_.raw }) }
}

# ============================================================================
# SECTION 8 - Domainlisten + Reports
#   - Resolve-DomainList baut eine eindeutige Domainliste (manuell + Suche).
#   - Invoke-DomainAudit fuehrt alle Checks fuer eine Domain aus.
#   - Danach werden die Domains nacheinander geprueft.
# ============================================================================
function Resolve-DomainList {
  param([string[]]$Manual,[string[]]$SearchPatterns)

  $result = [System.Collections.Generic.List[string]]::new()
  $seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

  if ($Manual) {
    foreach ($m in $Manual) {
      if ([string]::IsNullOrWhiteSpace($m)) { continue }
      $clean = $m.Trim().TrimEnd('.')
      if ($clean -and $seen.Add($clean)) { $result.Add($clean) }
    }
  }

  if ($SearchPatterns) {
    foreach ($pattern in $SearchPatterns) {
      if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
      $pClean = $pattern.Trim()
      $zones  = @( Get-Zones -Search $pClean )
      if ($zones.Count -eq 0) {
        Write-Warning ('DomainSearch "{0}" lieferte keine Treffer.' -f $pClean)
        continue
      }
      Write-Info ('DomainSearch "{0}" -> {1} Treffer' -f $pClean, $zones.Count)
      foreach ($z in $zones) {
        $nameProp = if ($z.PSObject.Properties.Name -contains 'zone_name') { $z.zone_name } else { $null }
        if ([string]::IsNullOrWhiteSpace($nameProp)) { continue }
        $clean = (Remove-TrailingDot $nameProp).Trim()
        if ($clean -and $seen.Add($clean)) { $result.Add($clean) }
      }
    }
  }

  $result
}

function Invoke-DomainAudit {
  param(
    [Parameter(Mandatory=$true)][string]$Domain,
    [Parameter(Mandatory=$true)][string]$AltRootValue,
    [switch]$StrictMode,
    [switch]$VerboseZoneInfo
  )

  $canonical = $Domain.Trim().TrimEnd('.')
  Write-Host ('Pruefe {0} ...' -f $canonical) -ForegroundColor Cyan

  $zone = Get-PrimaryZoneForFqdn -Fqdn $canonical
  $searchTerms = Get-RecordSearchTerms -Domain $canonical -Zone $zone
  if ($VerboseZoneInfo) {
    if ($zone) {
      Write-Info ('Zone: {0} (#{1}) dnssec={2} status={3}' -f $zone.zone_name,$zone.id,$zone.dnssec,$zone.status)
    } else {
      Write-Warning 'Keine passende Zone gefunden.'
    }
  }

  $zoneId = $null
  if ($zone) {
    if ($zone.PSObject.Properties.Name -contains 'id' -and $zone.id) {
      $zoneId = [int]$zone.id
    }
  } else {
    Write-Warning '[Fallback] Suche ohne zone_id - Ergebnisse koennen unvollstaendig sein.'
  }

  $mx   = Test-MX     -Domain $canonical -ZoneId $zoneId -SearchTerms $searchTerms
  $spf  = Test-SPF    -Domain $canonical -ZoneId $zoneId -SearchTerms $searchTerms
  $dmarc= Test-DMARC  -Domain $canonical -ZoneId $zoneId -SearchTerms $searchTerms
  $dkim = Test-DKIM   -Domain $canonical -DomainZoneId $zoneId -AltRoot $AltRootValue -SearchTerms $searchTerms
  $srv  = Test-SRV443 -Domain $canonical -ZoneId $zoneId -SearchTerms $searchTerms

  $fail = @()
  $warn = @()
  if (-not @($mx).Count) { $fail += 'mx' }
  if (-not $spf.present) { $fail += 'spf' } elseif ($spf.warnNoAll) { $warn += 'spf:no -all' }
  if (-not $dmarc.present) { $fail += 'dmarc' } elseif ($dmarc.policyWarn) { $warn += 'dmarc:p=none' }
  if (-not $dkim.present) { $fail += 'dkim' }
  if (-not $srv.present)  { $fail += 'srv' } elseif ($srv.wrongPort) { $fail += 'srv:port!=443' }

  if ($StrictMode) {
    if ($warn -contains 'spf:no -all')  { $fail += 'spf:no -all';  $warn = $warn | Where-Object { $_ -ne 'spf:no -all' } }
    if ($warn -contains 'dmarc:p=none') { $fail += 'dmarc:p=none'; $warn = $warn | Where-Object { $_ -ne 'dmarc:p=none' } }
  }

  $status = 'OK'
  if     ($fail.Count -gt 0) { $status = 'FAIL: ' + ($fail -join ', ') }
  elseif ($warn.Count -gt 0) { $status = 'WARN: ' + ($warn -join ', ') }

  [pscustomobject]@{
    domain = $canonical
    status = $status
    checks = [pscustomobject]@{
      mx     = @{ present = (@($mx).Count -gt 0);                     found =  ([string[]](ConvertTo-CleanArray ($mx | ForEach-Object { $_.raw }))) }
      spf    = @{ present = $spf.present;  warnNoAll = $spf.warnNoAll; found =  ([string[]](ConvertTo-CleanArray $spf.found)) }
      dmarc  = @{ present = $dmarc.present; policyWarn = $dmarc.policyWarn; found =  ([string[]](ConvertTo-CleanArray $dmarc.found)) }
      dkim   = @{ present = $dkim.present;                              found =  ([string[]](ConvertTo-CleanArray $dkim.found)) }
      srv443 = @{ present = $srv.present;   wrongPort = $srv.wrongPort;  found =  ([string[]](ConvertTo-CleanArray $srv.found)) }
    }
  }
}

  $manualDomainInputs = Expand-InputCollection -Items $Domains
  $searchPatternInputs = Expand-InputCollection -Items $DomainSearch
  $domainInputs = Resolve-DomainList -Manual $manualDomainInputs -SearchPatterns $searchPatternInputs
  if ($domainInputs.Count -eq 0) {
    $fallback = Import-FallbackDomains
    if ($fallback.Domains.Count -gt 0) {
      Write-Warning ('Keine Domains ueber Parameter gefunden. Verwende "{0}" ({1} Eintraege).' -f $fallback.Source, $fallback.Domains.Count)
      $domainInputs = Resolve-DomainList -Manual $fallback.Domains -SearchPatterns @()
    }
  }
  if ($domainInputs.Count -eq 0) {
    throw 'Keine Domains gefunden. Uebergib -Domains oder -DomainSearch.'
  }

Write-Info ('Starte Checks fuer {0} Domains.' -f $domainInputs.Count)

$domainReports = foreach ($domain in $domainInputs) {
  Invoke-DomainAudit -Domain $domain -AltRootValue $AltRoot -StrictMode:$Strict -VerboseZoneInfo:$VerboseZones
}

# ============================================================================
# SECTION 8B - Zusammenfassung (Funktionen)
#   - Erzeugt Tabellenzeilen und formatiert sie als Text.
# ============================================================================
function Get-SummaryRows {
  param(
    [Parameter(Mandatory=$true)][object[]]$DomainReports,
    [switch]$StrictMode
  )

  foreach ($r in $DomainReports) {
    [pscustomobject]@{
      Domain = $r.domain
      Status = $r.status
      MX     = if ($r.checks.mx.present) { 'OK' } else { '--' }
      SPF    = if ($r.checks.spf.present) {
                 if ($r.checks.spf.warnNoAll -and -not $StrictMode) { 'WARN' }
                 elseif ($r.checks.spf.warnNoAll -and $StrictMode)  { 'FAIL' }
                 else { 'OK' }
               } else { '--' }
      DMARC  = if ($r.checks.dmarc.present) {
                 if ($r.checks.dmarc.policyWarn -and -not $StrictMode) { 'WARN' }
                 elseif ($r.checks.dmarc.policyWarn -and $StrictMode)  { 'FAIL' }
                 else { 'OK' }
               } else { '--' }
      DKIM   = if ($r.checks.dkim.present) { 'OK' } else { '--' }
      SRV443 = if ($r.checks.srv443.present) {
                 if ($r.checks.srv443.wrongPort) { 'FAIL' } else { 'OK' }
               } else { '--' }
    }
  }
}

function Format-SummaryTextList {
  param([Parameter(Mandatory=$true)][object[]]$Rows)

  if ($Rows.Count -eq 0) { return '' }

  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($row in $Rows) {
    $lines.Add(('Domain: {0}' -f $row.Domain)) | Out-Null
    $lines.Add(('  Status: {0}' -f $row.Status)) | Out-Null
    $lines.Add(('  Checks: MX={0} SPF={1} DMARC={2} DKIM={3} SRV443={4}' -f $row.MX, $row.SPF, $row.DMARC, $row.DKIM, $row.SRV443)) | Out-Null
    $lines.Add('') | Out-Null
  }
  ($lines -join "`n").TrimEnd()
}

# ============================================================================
# SECTION 9 - Zusammenfassung und Ausgabe
#   - Optional: Tabelle mit OK/WARN/FAIL anzeigen.
#   - Immer: JSON-Report erzeugen und ausgeben.
#   - Optional: JSON in Datei speichern.
# ============================================================================
$summaryRows = @(Get-SummaryRows -DomainReports $domainReports -StrictMode:$Strict)
$summaryTable = Format-SummaryTextList -Rows $summaryRows

if ($Summary) {
  Write-Host "`n=== Zusammenfassung ===`n" -ForegroundColor Cyan
  Write-Host $summaryTable
  Write-Host ''
}

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
  Write-Info ('Report gespeichert unter {0}' -f $OutputJson)
}

# ============================================================================
# SECTION 10 - Exitcodes
#   - Wenn irgendein FAIL -> exit 2
#   - Wenn nur WARN -> exit 1
#   - Sonst -> exit 0
# ============================================================================
$hasFail = $domainReports | Where-Object { $_.status -like 'FAIL*' }
$hasWarn = $domainReports | Where-Object { $_.status -like 'WARN*' }

if ($hasFail) {
  $summaryForMail = $summaryTable
  Send-ErrorReport -ReportJson $reportJson -DomainReports $domainReports -ReportPath $OutputJson -SummaryText $summaryForMail
  exit 2
}
elseif ($hasWarn) { exit 1 }
else { exit 0 }
