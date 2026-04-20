#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║           ThreatHasher - Nmap + Shodan Recon Tool         ║
║           Escaneo de puertos, hosts y CVEs                ║
║                      created by 0x21                      ║
╚═══════════════════════════════════════════════════════════╝
"""

import argparse
import json
import csv
import sys
import os
from datetime import datetime

# ──────────────────────────────────────────────
# Dependencias: pip install python-nmap shodan
# ──────────────────────────────────────────────
try:
    import nmap
except ImportError:
    print("[!] Instala python-nmap: pip install python-nmap")
    sys.exit(1)

try:
    import shodan
except ImportError:
    print("[!] Instala shodan: pip install shodan")
    sys.exit(1)


# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "TU_API_KEY_AQUI")

BANNER = """
\033[1;31m
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   
\033[1;37m
  ██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ 
  ██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
  ███████║███████║███████╗███████║█████╗  ██████╔╝
  ██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
  ██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
\033[0m
\033[90m                      [ Auto-Recon Tool ]
                         created by \033[1;31m0x21\033[0m
"""


# ─────────────────────────────────────────────
# MÓDULO NMAP
# ─────────────────────────────────────────────
def nmap_scan(target: str, ports: str = "1-1024", args: str = "-sV -O --script vuln") -> dict:
    """
    Escanea un host con Nmap.
    - Detección de versiones (-sV)
    - Detección de OS (-O)
    - Scripts de vulnerabilidades (--script vuln)
    """
    print(f"\n[*] Iniciando escaneo Nmap en: {target}")
    print(f"    Puertos: {ports} | Args: {args}")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, ports=ports, arguments=args)
    except nmap.PortScannerError as e:
        print(f"[!] Error en Nmap: {e}")
        return {}

    results = {}

    for host in nm.all_hosts():
        print(f"\n  [+] Host: {host} ({nm[host].hostname()})")
        print(f"      Estado: {nm[host].state()}")

        host_data = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "os": [],
            "ports": [],
            "vulns": []
        }

        # Sistema operativo
        if "osmatch" in nm[host]:
            for os_match in nm[host]["osmatch"][:3]:
                os_info = {
                    "name": os_match.get("name", "Desconocido"),
                    "accuracy": os_match.get("accuracy", "0")
                }
                host_data["os"].append(os_info)
                print(f"      OS: {os_info['name']} ({os_info['accuracy']}% confianza)")

        # Puertos y servicios
        for proto in nm[host].all_protocols():
            ports_list = sorted(nm[host][proto].keys())
            for port in ports_list:
                port_info = nm[host][proto][port]
                port_data = {
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state", ""),
                    "service": port_info.get("name", ""),
                    "version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                    "extrainfo": port_info.get("extrainfo", "")
                }
                host_data["ports"].append(port_data)
                print(f"      [{port_data['state'].upper()}] {port}/{proto} - "
                      f"{port_data['service']} {port_data['version']}")

                # Vulnerabilidades detectadas por scripts NSE
                if "script" in port_info:
                    for script_name, script_output in port_info["script"].items():
                        if any(kw in script_name.lower() for kw in ["vuln", "cve", "exploit"]):
                            vuln = {
                                "port": port,
                                "script": script_name,
                                "output": script_output[:500]
                            }
                            host_data["vulns"].append(vuln)
                            print(f"        [!] VULN [{script_name}]: {script_output[:100]}...")

        results[host] = host_data

    return results


# ─────────────────────────────────────────────
# MÓDULO SHODAN
# ─────────────────────────────────────────────
def shodan_lookup(target: str) -> dict:
    """
    Busca información de un host en Shodan.
    Incluye puertos abiertos, banners, CVEs y organización.
    """
    print(f"\n[*] Consultando Shodan para: {target}")

    if SHODAN_API_KEY == "TU_API_KEY_AQUI":
        print("[!] Configura tu SHODAN_API_KEY (variable de entorno o en el script)")
        return {}

    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        host_info = api.host(target)
    except shodan.APIError as e:
        print(f"[!] Error Shodan: {e}")
        return {}

    result = {
        "ip": host_info.get("ip_str", target),
        "org": host_info.get("org", "N/A"),
        "isp": host_info.get("isp", "N/A"),
        "country": host_info.get("country_name", "N/A"),
        "city": host_info.get("city", "N/A"),
        "os": host_info.get("os", "N/A"),
        "last_update": host_info.get("last_update", "N/A"),
        "ports": host_info.get("ports", []),
        "hostnames": host_info.get("hostnames", []),
        "domains": host_info.get("domains", []),
        "tags": host_info.get("tags", []),
        "vulns": [],
        "services": []
    }

    # CVEs encontrados por Shodan
    if "vulns" in host_info:
        for cve_id, cve_data in host_info["vulns"].items():
            vuln = {
                "cve": cve_id,
                "cvss": cve_data.get("cvss", "N/A"),
                "summary": cve_data.get("summary", "")[:200]
            }
            result["vulns"].append(vuln)

    # Servicios / banners
    for item in host_info.get("data", []):
        service = {
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
            "banner": item.get("data", "")[:300].strip()
        }
        result["services"].append(service)

    # Mostrar en terminal
    print(f"\n  [+] IP: {result['ip']}")
    print(f"      Organización: {result['org']} | ISP: {result['isp']}")
    print(f"      Ubicación: {result['city']}, {result['country']}")
    print(f"      OS: {result['os']}")
    print(f"      Puertos abiertos: {result['ports']}")
    print(f"      Hostnames: {result['hostnames']}")

    if result["vulns"]:
        print(f"\n  [!] CVEs detectados por Shodan ({len(result['vulns'])}):")
        for v in result["vulns"]:
            print(f"      - {v['cve']} | CVSS: {v['cvss']}")
            if v["summary"]:
                print(f"        {v['summary'][:120]}...")
    else:
        print("  [✓] Sin CVEs registrados en Shodan")

    return result


# ─────────────────────────────────────────────
# MÓDULO EXPORTACIÓN
# ─────────────────────────────────────────────
def export_json(data: dict, filename: str):
    """Exporta los resultados en formato JSON."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"\n[✓] Resultados exportados en JSON: {filename}")


def export_csv(data: dict, filename: str):
    """
    Exporta un resumen de vulnerabilidades en CSV.
    Columnas: target, source, cve/vuln, cvss, port, detalle
    """
    rows = []

    # Vulns de Nmap
    for host, host_data in data.get("nmap", {}).items():
        for vuln in host_data.get("vulns", []):
            rows.append({
                "target": host,
                "source": "Nmap NSE",
                "cve": vuln.get("script", "N/A"),
                "cvss": "N/A",
                "port": vuln.get("port", "N/A"),
                "detalle": vuln.get("output", "")[:200]
            })

    # CVEs de Shodan
    for host, host_data in data.get("shodan", {}).items():
        for vuln in host_data.get("vulns", []):
            rows.append({
                "target": host,
                "source": "Shodan",
                "cve": vuln.get("cve", "N/A"),
                "cvss": vuln.get("cvss", "N/A"),
                "port": "N/A",
                "detalle": vuln.get("summary", "")[:200]
            })

    if not rows:
        rows.append({"target": "N/A", "source": "N/A", "cve": "Sin vulnerabilidades detectadas",
                     "cvss": "N/A", "port": "N/A", "detalle": ""})

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["target", "source", "cve", "cvss", "port", "detalle"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[✓] Vulnerabilidades exportadas en CSV: {filename}")


# ─────────────────────────────────────────────
# FUNCIÓN PRINCIPAL
# ─────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="AutoRecon - Reconocimiento automatizado con Nmap + Shodan",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="IP o rango de IPs objetivo (ej: 192.168.1.1 o 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Puertos a escanear (default: 1-1024)")
    parser.add_argument("--nmap-args", default="-sV -O --script vuln",
                        help="Argumentos de Nmap (default: -sV -O --script vuln)")
    parser.add_argument("--no-nmap", action="store_true", help="Omitir escaneo Nmap")
    parser.add_argument("--no-shodan", action="store_true", help="Omitir búsqueda en Shodan")
    parser.add_argument("-o", "--output", default=None,
                        help="Prefijo de archivo de salida (default: recon_<timestamp>)")
    parser.add_argument("--json", action="store_true", help="Exportar resultados a JSON")
    parser.add_argument("--csv", action="store_true", help="Exportar vulnerabilidades a CSV")

    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output or f"recon_{timestamp}"

    all_results = {
        "meta": {
            "target": args.target,
            "timestamp": timestamp,
            "tool": "AutoRecon v1.0"
        },
        "nmap": {},
        "shodan": {}
    }

    # ── Nmap ──
    if not args.no_nmap:
        nmap_results = nmap_scan(args.target, ports=args.ports, args=args.nmap_args)
        all_results["nmap"] = nmap_results
    else:
        print("[*] Escaneo Nmap omitido.")

    # ── Shodan ──
    if not args.no_shodan:
        # Shodan solo acepta IPs individuales
        targets = [args.target]
        if "/" in args.target:
            print("[!] Shodan no soporta rangos CIDR. Usando solo la IP base.")
            targets = [args.target.split("/")[0]]

        for ip in targets:
            shodan_result = shodan_lookup(ip)
            if shodan_result:
                all_results["shodan"][ip] = shodan_result
    else:
        print("[*] Búsqueda Shodan omitida.")

    # ── Resumen de vulnerabilidades ──
    print("\n" + "═" * 60)
    print("  RESUMEN DE VULNERABILIDADES")
    print("═" * 60)

    total_nmap_vulns = sum(len(h.get("vulns", [])) for h in all_results["nmap"].values())
    total_shodan_vulns = sum(len(h.get("vulns", [])) for h in all_results["shodan"].values())

    print(f"  Nmap NSE:  {total_nmap_vulns} hallazgo(s)")
    print(f"  Shodan:    {total_shodan_vulns} CVE(s)")
    print(f"  Total:     {total_nmap_vulns + total_shodan_vulns}")
    print("═" * 60)

    # ── Exportación ──
    if args.json or not (args.json or args.csv):
        export_json(all_results, f"{output_prefix}.json")

    if args.csv:
        export_csv(all_results, f"{output_prefix}_vulns.csv")

    print("\n[✓] Reconocimiento completado.\n")


if __name__ == "__main__":
    main()
