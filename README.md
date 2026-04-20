```
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██████╗
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
  ███████║███████║███████╗███████║█████╗  ██████╔╝
  ██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
  ██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

                 [ Nmap + Shodan Recon Tool v2.0 ]
                          created by 0x21
```

![Version](https://img.shields.io/badge/version-2.0-cc2200?style=flat-square)
![Python](https://img.shields.io/badge/python-3.8+-cc2200?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-555?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-555?style=flat-square)
![Security](https://img.shields.io/badge/offensive-security-cc2200?style=flat-square)

---

## // DESCRIPCION

ThreatHasher es una herramienta de reconocimiento ofensivo de linea de comandos disenada
para automatizar la fase de recon en auditorias de seguridad. Integra Nmap y la API de
Shodan en un unico flujo interactivo para descubrir puertos, identificar servicios, detectar
CVEs y exportar resultados en multiples formatos para su inclusion en informes.

---

## // MODULOS

```
[01] NMAP SCAN    6 perfiles. Deteccion de OS, versiones y scripts NSE vuln.
[02] SHODAN       Lookup de IP, query search con filtros, CVEs con CVSS.
[03] DNS & PING   DNS forward/reverse, ping sweep de subredes, nslookup.
[04] EXPORT       JSON completo, CSV de CVEs, reporte TXT para informes.
```

---

## // STACK TECNICO

```
[ Python 3.8+ ]  [ python-nmap ]  [ Shodan API ]  [ Nmap 7.x ]  [ JSON/CSV/TXT ]
```

---

## // REQUISITOS

```
COMPONENTE       VERSION    NOTAS
────────────────────────────────────────────────────────
Python           3.8+       Requerido
Nmap             7.x        Instalado en el sistema
python-nmap      ultima     pip install python-nmap
shodan           ultima     pip install shodan
Shodan API Key   —          account.shodan.io (gratuita)
```

---

## // INSTALACION

**Debian / Ubuntu**
```bash
sudo apt install nmap python3 python3-pip
pip install python-nmap shodan
```

**Arch Linux**
```bash
sudo pacman -S nmap python python-pip
pip install python-nmap shodan
```

**macOS**
```bash
brew install nmap
pip install python-nmap shodan
```

**Configurar API Key**
```bash
export SHODAN_API_KEY="tu_api_key_aqui"
```

**Ejecutar**
```bash
python3 threathsher.py
```

---

## // PERFILES NMAP

```
PERFIL            PUERTOS     ARGUMENTOS              USO
────────────────────────────────────────────────────────────────────
Rapido            Top 100     -T4 -F                  Reconocimiento inicial
Estandar          1-1024      -sV -O -T4              Version y OS
Completo          1-65535     -sV -T4                 Escaneo exhaustivo
Vulnerabilidades  1-1024      -sV -O --script vuln    Deteccion de CVEs
Stealth SYN       1-1024      -sS -T2 -O              Sigiloso, root
Personalizado     definido    definidos               Argumentos manuales
```

---

## // SALIDA EN TERMINAL

```
ThreatHasher > 1

  [INFO]   Target  : 192.168.1.1
  [INFO]   Puertos : 1-1024
  [INFO]   Args    : -sV -O --script vuln
  ----------------------------------------------------------------
  [HOST]   192.168.1.1  (router.local)  [UP]
           OS : Linux 4.15 (98%)
  [OPEN ]  22   /tcp  ssh    OpenSSH 7.9
  [OPEN ]  80   /tcp  http   Apache 2.4.38
  [OPEN ]  443  /tcp  https  Apache 2.4.38
  [VULN]   http-vuln-cve2017-5638
           Apache Struts 2 RCE vulnerability...
  ----------------------------------------------------------------
  [OK]     Escaneo finalizado. 1 host(s) procesados.
```

---

## // FLUJO DE USO RECOMENDADO

```
[01] Configurar Shodan API Key en menu [5]
[02] Nmap rapido para identificar puertos abiertos
[03] Nmap vuln sobre hosts de interes
[04] Shodan lookup para obtener CVEs historicos
[05] DNS para resolver hostnames y ampliar perimetro
[06] Exportar resultados en JSON + CSV + TXT
```

---

## // AVISO LEGAL

```
ADVERTENCIA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Esta herramienta es exclusivamente para uso etico y autorizado.
Escanea unicamente sistemas sobre los que dispones de permiso
explicito por escrito. El uso no autorizado puede ser constitutivo
de delito segun la legislacion vigente en tu pais.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

`threathsher v2.0` — `nmap + shodan recon tool` — `created by 0x21`
