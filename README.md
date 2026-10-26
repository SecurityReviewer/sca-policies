# sca-policies

Policy SCA (Security Configuration Assessment) che Cyber Reviewer aggiunge a quelle di Wazuh 5, con i generatori e gli scanner che
le alimentano. Originali in `srcyberreviewer`: `ruleset/sca/windows/`, `ruleset/sca/applications/`, `wodles/apk-static/`,
`wodles/secrets-scan/`.

## Policy (`policies/`)

| File | Controlli | ID | Cosa verifica |
|---|---|---|---|
| `cis_win2008r2.yml` | 251 | 37000-37250 | Windows Server 2008 R2. **Derivata** dalla policy Wazuh per Windows Server 2012 R2 (v3.0.0): tolti i controlli che richiedono funzioni successive a Windows 6.1, id rinumerati. **Non è il benchmark CIS ufficiale** (la checklist CIS è distribuita con registrazione e licenza SecureSuite). Le etichette di conformità sono quelle della policy di origine. |
| `ms_office_2013.yml` | 26 | 61100-61125 | Chiavi di policy macchina `HKLM\SOFTWARE\Policies\Microsoft\Office\15.0`: macro, blocco dei file da Internet, accesso al modello a oggetti e altro. Per l'agente a 32 bit su Windows a 64 bit usa regole su file, perché la vista a 64 bit del registro non è visibile. |
| `ms_office_2016.yml` | 26 | 61000-61025 | Come sopra per `16.0`. |
| `android_apk_static.yml` | 15 | 60001-60015 | Analisi statica di un APK estratto su un host Linux con agente: `debuggable`, backup, traffico in chiaro, permessi e simili (NIS2 21.2.e, ISO A.8.26/A.8.28, GDPR art. 32, OWASP MASVS). Un controllo superato non è una prova di sicurezza. |
| `secrets_scan_unix.yml` | 5 | 62001-62005 | Chiavi private, credenziali cloud, token di servizi, credenziali nel codice o nelle configurazioni, salute della scansione. |
| `secrets_scan_windows.yml` | 5 | 62101-62105 | Gli stessi controlli per Windows. |

Il modulo SCA carica **tutte** le policy presenti in `ruleset/sca/`: quelle dei segreti e quella APK si registrano a parte
(vedi i README degli scanner) quando non si vuole che girino su ogni agente.

## Generatori (`generators/`)
- `make_ms_office_policy.py <uscita.yml> <15.0|16.0>`: genera le policy Office 2013 e 2016.
- `make_policy.py`: rigenera la policy APK del prodotto oppure una per singola applicazione (`--apk`, `--id`, `--name`).

## Scanner (`scanners/`)
- `apk-static/`: `apk_check.py` (solo libreria standard: parser AXML e scansione delle stringhe dex) e 6 test unitari.
- `secrets-scan/`: `secrets_scan.py` e `secrets_scan.ps1`, `patterns.json`, test. Motore principale TruffleHog; lo scanner custom è di
  riserva. Il risultato è un evento per finding (file, riga, categoria, tipo) **senza il valore del segreto**.

## Uso
Copiare il file `.yml` in `ruleset/sca/<cartella>/` del manager, registrarlo in `etc/templates/config/generic/sca.manager.files`
(e in `src/win32/wazuh-installer.wxs` per l'MSI Windows) e distribuirlo agli agenti. Le istruzioni degli scanner sono nei loro README.

## Licenza
GNU GPL versione 2 (vedi `LICENSE`), la stessa di Wazuh da cui `cis_win2008r2.yml` deriva (intestazione del file). Il testo dei benchmark
CIS richiamati nelle policy appartiene a CIS e non è coperto dalla GPL.
