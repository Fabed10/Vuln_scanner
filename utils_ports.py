def parser_ports(saisie):

    if not saisie or not saisie.strip():
        return None

    ports = []
    saisie = saisie.replace(" ", "")  # Enlever tous les espaces

    # Séparer par virgules
    parties = saisie.split(",")

    for partie in parties:
        if not partie:
            continue

        # Range : "1-1024"
        if "-" in partie:
            try:
                debut, fin = partie.split("-")
                debut = int(debut)
                fin = int(fin)

                if debut < 1 or debut > 65535 or fin < 1 or fin > 65535:
                    print(f"[!] Erreur : ports hors limites (1-65535) → {partie}")
                    return None

                if debut > fin:
                    print(f"[!] Erreur : range invalide (début > fin) → {partie}")
                    return None

                ports.extend(range(debut, fin + 1))

            except ValueError:
                print(f"[!] Erreur : format range invalide → {partie}")
                return None

        # Port unique : "22"
        else:
            try:
                port = int(partie)
                if port < 1 or port > 65535:
                    print(f"[!] Erreur : port hors limites (1-65535) → {port}")
                    return None
                ports.append(port)

            except ValueError:
                print(f"[!] Erreur : port invalide → {partie}")
                return None

    if not ports:
        return None

    # Retourner liste triée et dédupliquée
    return sorted(set(ports))



if __name__ == "__main__":
    tests = [
        ("22, 80, 443",         [22, 80, 443]),
        ("1-10",                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        ("22, 80, 100-103",     [22, 80, 100, 101, 102, 103]),
        ("80",                  [80]),
        ("22,80,443",           [22, 80, 443]),  # sans espaces
        ("22, 22, 80",          [22, 80]),       # doublons éliminés
        ("100-95",              None),           # range inversé
        ("99999",               None),           # hors limite
        ("abc",                 None),           # invalide
        ("",                    None),           # vide
    ]

    print("Tests du parser de ports :\n")
    ok = 0
    for saisie, attendu in tests:
        resultat = parser_ports(saisie)
        status = "✅" if resultat == attendu else "❌"
        if resultat == attendu:
            ok += 1
        print(f"{status}  '{saisie}' → {resultat}")

    print(f"\nScore : {ok}/{len(tests)}")