import requests
import json
import time

API_KEYS = [
    "eb155a0cc4f88ad48a67863c3d1db08b0fa46b6336f22810f5694f20e790c90eea481d7f66047e31",
    "c6ec97f1658fa3dfb28231125406bc183b7d6d24f1e0c24e3a49b43ccf515aec0812a71f462dd947",
]
github_urls = [
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-40k.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-ab.txt"
]
OUTPUT_FILE = "dataset_malicious_ips.json"
category_map = {
    3: "phishing",
    4: "ddos",
    5: "ftp_bruteforce",
    9: "tor",
    14: "port_scan",
    15: "hacking",
    18: "bruteforce",
    19: "malware",
    20: "malware",
    22: "ssh_attack",
    23: "spam",      
    24: "ransomware" 
}
def check_ip(ip,current_key_index=0):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }

    for key_index in range(current_key_index, len(API_KEYS)):
        try:
            headers = {
                "Key": API_KEYS[key_index],
                "Accept": "application/json"
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            # Si limite atteinte, passer à la prochaine clé
            if response.status_code == 429:
                print(f"Limite API pour clé {key_index} atteinte, changement de clé")
                time.sleep(1)
                continue  # recommence la boucle avec la clé suivante

            # Si autre erreur HTTP
            if response.status_code != 200:
                print(f"Erreur HTTP {response.status_code} pour IP {ip}")
                return None, key_index
            data = response.json()["data"]
            score = data["abuseConfidenceScore"]

            # Ignorer les IP clean
            if score == 0:
                print(f"IP {ip} -> clean")
                return None, key_index
            reports = data.get("reports", [])
            threats = set()

            # Récupérer toutes les catégories d'attaque
            for report in reports:
                for cat in report.get("categories", []):
                    if cat in category_map:
                        threats.add(category_map[cat])
            if not threats:
                threats.add("reported_for_abuse")
            print(f"IP {ip} -> threat found: {list(threats)}")
            return {
                "type": "ip",
                "value": ip,
                "threat": list(threats)
            }, key_index
        except Exception as e:
            print(f"Erreur analyse IP {ip}: {e}")
            return None, len(API_KEYS)-1 

    # Si toutes les API Keys sont épuisées
    print("Toutes les API Keys sont épuisées ou erreur persistante pour cette IP :", ip)
    return None

def main():
    results = []
    count = 0
    malicious_count = 0
    current_key = 0
    for feed in github_urls:
        print("===Lecture du feed=== :", feed)
        try:
            response = requests.get(feed, timeout=10)
            lines = response.text.splitlines()
            for line in lines:
             if line and not line.startswith("#"):
                 ip = line.split()[0]
                 print("Analyse de l'IP :", ip)
                 result, new_key = check_ip(ip,current_key)
                 current_key = new_key
                 if result:
                     results.append(result)
                     malicious_count += 1
                     print(f"IP malveillante n°{malicious_count} : {ip}")
                 time.sleep(1) 
                 if malicious_count >= 10:
                     print("Limite de 10 IP malveillantes atteinte !")
                     with open(OUTPUT_FILE, "w") as f:
                         json.dump(results, f, indent=4)
                     return 
        except:
            print("Erreur récupération feed")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=4)

    print("\n============================")
    print("Analyse terminée")
    print("IP analysées :", count)
    print("Menaces trouvées :", len(results))
    print("Résultat écrit dans", OUTPUT_FILE)


if __name__ == "__main__":
    main()