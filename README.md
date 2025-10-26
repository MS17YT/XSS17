# MS17 — XSS Scanner Ultimate

![Python](https://img.shields.io/badge/Python-2.7-yellow?logo=python)
![Status](https://img.shields.io/badge/Status-Community%20Tool-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)
![Bug Bounty](https://img.shields.io/badge/Use-Bug%20Bounty%20%2F%20Pentest-red)

> **MS17** è uno scanner XSS orientato al bug‑bounty, scritto in **Python 2**. Ideale per penetration tester e bug hunter che vogliono un tool rapido, menu‑driven e con supporto Selenium per verifiche dinamiche.

---

## ⚡ Requisiti (IMPORTANTE: **Python**)
Il tool è stato scritto per **Python** — **non usarlo con Python 3** senza aver prima adattato il codice.  
Installare dipendenze (usando pip per Python, es. `pip` o un virtualenv Python):
```bash
# crea un virtualenv Python (se virtualenv è installato)
virtualenv -p /usr/bin/python venv
source venv2/bin/activate

# oppure usa pip diretto
pip install -r requirements.txt
```

Esempio `requirements.txt` (compatibile Python2):
```
requests==2.21.0
colorama==0.3.9
selenium==3.141.0
urllib3==1.24.3
```
> Nota: usa versioni compatibili con Python2. Alcune versioni più recenti delle librerie non supportano più Python2.


---

## 🚀 Caratteristiche principali
- Scansione automatizzata su parametri **GET**, **POST**, **HEADERS**, **DOM**.  
- **Verifica dinamica con Selenium** (cattura esecuzione `alert()` e segnala XSS reali).  
- Generatore integrato di payload: **basic**, **advanced**, **polyglot**, **DOM**, **WAF‑bypass**.  
- Multithreading semplice per scansioni veloci.  
- Report in **JSON** con metadati di scansione (timestamp, durata, config).  
- Modalità interattiva (menu) e opzioni configurabili nello script.  

---

## 🛠️ Installazione veloce
1. Posiziona `MS17.py` nella directory del progetto.  
2. Crea e attiva un virtualenv Python2 (consigliato) oppure usa il tuo interpreter Python2 di sistema.  
3. Installa le dipendenze per Python2:
```bash
pip install -r requirements.txt
```

4. Assicurati di avere Chrome/Firefox e relativo driver nel PATH per usare Selenium (Chromedriver / geckodriver compatibili con la versione del browser).

---

## ▶️ Uso base
> Esempio: avvia lo script in modalità interattiva (default menu)
```bash
python XSS17.py
```

Puoi lanciare comandi non interattivi, un esempio generico potrebbe essere:
```bash
python XSS17.py --target "https://vittima.local/page.php?id=1" --payloads payloads.txt --methods GET POST --threads 8 --timeout 10 --insecure
```
> Nota: `--insecure` (se presente) disabilita la verifica SSL. Usalo solo per test autorizzati.

---

## 🔎 Report di esempio (estratto)
```json
{
  "scan_info": {
    "target": "https://example.com/page.php?id=1",
    "timestamp": "2025-10-26T14:32:00",
    "duration_seconds": 8.5
  },
  "vulnerabilities": [
    {
      "type": "GET",
      "url": "https://example.com/page.php?id=<script>alert(1)</script>",
      "payload": "<script>alert(1)</script>",
      "confidence": "HIGH"
    }
  ],
  "scan_config": {
    "threads": 10,
    "timeout": 15,
    "methods": ["GET", "POST"]
  }
}
```

---

## 🔧 Consigli d'uso e Best Practices
- **Usa solo target autorizzati.** Testare senza permesso è illegale.  
- Parti con payload non distruttivi (`alert(1)`) prima di provare payload più aggressivi.  
- Regola i thread (5–15 consigliati) per non sovraccaricare il target.  
- Usa un proxy (Burp Suite) per analizzare le richieste/responses.  
- Abilita Selenium solamente quando strettamente necessario (maggiore overhead).

---

## 🩺 Note tecniche e limitazioni
- Il codice è stato aggiornato per aggiungere logging e un flag per SSL (`--insecure`), ma alcune modifiche (es. conversione globale di `print` in `logging`) possono essere sensibili per l'interfaccia menu-driven tipica di Python2. Se noti comportamenti strani nell'output, segnalalo.  

---

## ⚠️ Avviso legale ed etico
Questo strumento è destinato esclusivamente ad uso etico: **penetration testing autorizzato, bug bounty e scopi formativi**. L'autore non è responsabile per danni o attività illegali commesse usando il software.

---

## 🧩 File inclusi in questa repository
- `XSS17.py` — script principale (Python 2)  
- `requirements.txt` — dipendenze compatibili Python2  
- `README.md` — questo file  
- `LICENSE` — MIT (opzionale)  

---

## 🤝 Contribuire
Contribuzioni e PR sono benvenute. Se mandi una PR, includi sempre una descrizione e un caso di test replicabile (target di prova o snippet).

---
