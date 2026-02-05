# DNS-Certifier

PowerShell-Skript zum Pruefen von Mail-DNS-Eintraegen (MX, SPF, DMARC, DKIM, Autodiscover/SRV443) fuer Domains.
Die Ergebnisse werden als JSON ausgegeben und optional per SMTP gemeldet.

## Features

- Prueft zentrale Mail-Records (MX, SPF, DMARC, DKIM, Autodiscover/SRV443)
- Unterstuetzt Domainlisten, Domain-Suche und Fallback-Dateien
- Liefert konsistente JSON-Ausgabe fuer Automation
- Optionaler SMTP-Fehlerbericht bei WARN/FAIL

## Voraussetzungen

- PowerShell 5.1 oder 7+
- Zugriff auf eine DNS-API mit Basic-Auth-Token

## Installation

Repository klonen und das Skript direkt ausfuehren:

```powershell
./Check-MailDns.ps1 -ApiBase https://dns-api.example.net -Domains example.com
```

## Konfiguration

### Environment-Variablen

- `DNS_API_TOKEN`: Basic-Auth-Token fuer die DNS-API
- `SmtpServer`, `SmtpPort`, `SmtpFrom`, `SmtpTo`, `SmtpUser`, `SmtpPassword`: SMTP-Konfiguration

### Parameteruebersicht (Auszug)

- `-ApiBase`: Basis-URL der DNS-API (ohne Slash am Ende)
- `-ApiToken`: Basic-Auth-Token (oder `DNS_API_TOKEN` als Env)
- `-Domains`: Liste der zu pruefenden Domains
- `-DomainSearch`: Suchmuster fuer `list_zones` (Wildcards moeglich)
- `-OutputJson`: Pfad fuer JSON-Report
- `-AltRoot`: Alternative Root fuer DKIM-Delegation
- `-IncludeDrafts`: Records mit Status `draft` einbeziehen
- `-VerboseZones`: Zusatzinfos zur Zone anzeigen
- `-DebugHttp`: HTTP-Aufrufe sichtbar machen
- `-Summary`: Tabelle vor JSON anzeigen
- `-VerboseOutput`: Detaillierte Fortschrittsmeldungen

## Nutzung

### Typische Aufrufe

```powershell
# Einzelne Domain, Ausgabe als Tabelle + JSON
./Check-MailDns.ps1 -ApiBase https://dns-api.example.net -Domains example.com -Summary

# Domains ueber Suche sammeln und Report speichern
./Check-MailDns.ps1 -ApiBase https://dns-api.example.net -DomainSearch "*.example.org" -OutputJson ./report.json
```

### Eingabe-Quellen fuer Domains

Es gibt drei Wege, Domains zu uebergeben:

1. **Direkt** ueber `-Domains`.
2. **Per Suche** ueber `-DomainSearch`, die intern `list_zones` abfragt.
3. **Fallback-Datei** `maildomains.txt` oder `smallmaildomains.txt` im Skriptordner,
   im Arbeitsverzeichnis oder in deren Elternverzeichnissen.

## Ausgabe und Exitcodes

- Standardausgabe ist immer JSON mit Zeitstempel und Ergebnissen.
- Optional wird eine Tabelle angezeigt (`-Summary`).
- Exitcode `0` bei OK, `1` bei WARN/FAIL.

## SMTP-Fehlerberichte

Wenn mindestens eine Domain WARN oder FAIL liefert und SMTP konfiguriert ist,
versendet das Skript einen Fehlerbericht.

**Erforderlich:** `-SmtpServer`, `-SmtpFrom`, `-SmtpTo`

Optionale Parameter:

- `-SmtpPort` (Standard: 25)
- `-SmtpUser`, `-SmtpPassword`
- `-SmtpUseSsl`
- `-SmtpSubject`

## Beispielausgabe (JSON)

```json
{
  "timestamp": "2024-01-01T10:00:00.0000000Z",
  "results": [
    {
      "domain": "example.com",
      "status": "OK",
      "checks": {
        "mx": { "present": true, "found": [] },
        "spf": { "present": true, "warnNoAll": false, "found": [] },
        "dmarc": { "present": true, "policyWarn": false, "found": [] },
        "dkim": { "present": true, "found": [] },
        "srv443": { "present": true, "wrongPort": false, "found": [] }
      }
    }
  ]
}
```

## Hinweise

- UTF-8-Speicherung empfohlen.
- Die API wird automatisch auf Erreichbarkeit geprueft.
- Mit `-DebugHttp` lassen sich Requests nachvollziehen.
