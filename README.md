# Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis
Projet cryptographie ISEN4 cybersécurité

Ce projet Java a pour objectif de **valider des certificats X.509** et leurs chaînes en vérifiant plusieurs aspects essentiels :  
- La **signature** (RSA ou ECDSA) du certificat.  
- Les **Key Usage** et les **Basic Constraints** pour déterminer si un certificat peut signer d'autres certificats.  
- Le **statut de révocation** via CRL et OCSP, avec mise en cache pour optimiser les performances.  
- La vérification de la signature RSA en utilisant des calculs sur grands nombres via `java.math.BigInteger`.

---

## Table des matières
- [Fonctionnalités](#fonctionnalités)
- [Architecture du projet](#architecture-du-projet)
- [Prérequis](#prérequis)
- [Compilation et Exécution](#compilation-et-exécution)
- [Utilisation](#utilisation)

---

## Fonctionnalités

- **Validation de certificats individuels :**  
  Charge un certificat en format DER ou PEM, affiche ses informations (sujet, émetteur, validité, numéro de série) et vérifie sa signature, sa validité temporelle, ainsi que ses extensions Key Usage et Basic Constraints.

- **Validation d'une chaîne de certificats :**  
  Vérifie récursivement la chaîne en s'assurant que chaque certificat est correctement signé par son émetteur, en remontant jusqu'au certificat racine auto-signé.

- **Vérification RSA avec `BigInteger` :**  
  Implémente manuellement la vérification de signature RSA en utilisant des opérations sur grands nombres pour démontrer le processus de déchiffrement et de comparaison du hash.

- **Vérification du statut de révocation via CRL et OCSP :**  
  Télécharge et analyse les CRL et/ou interroge un serveur OCSP pour déterminer si un certificat a été révoqué.  
  Un système de cache (en mémoire et/ou sur disque) a été mis en place pour éviter des téléchargements répétés des mêmes CRL.

---

## Architecture du projet

Le projet est structuré en deux classes principales :

- **`Main.java`**  
  Point d'entrée du projet. Cette classe gère l'interface en ligne de commande, le chargement des certificats (individuels ou en chaîne) et l'appel des différentes méthodes de vérification.

- **`ValidateCert.java`**  
  Contient l'ensemble des méthodes permettant de réaliser la validation :
  - Chargement des certificats (DER/PEM)
  - Vérification de la signature et des algorithmes de signature
  - Vérification des Key Usage et Basic Constraints
  - Validation de la chaîne de certificats (approche récursive)
  - Vérification du statut de révocation via CRL et OCSP
  - Vérification RSA manuelle avec `BigInteger`

---

## Prérequis

- **Java JDK 8 ou supérieur** (recommandé JDK 23 pour les dernières fonctionnalités).  
- **Bibliothèques tierces** :  
  - Bouncy Castle (pour la gestion des extensions ASN.1, OCSP et CRL)  
  - (Optionnel) Toute autre bibliothèque de cryptographie ou utilitaire selon vos besoins.

---

## Compilation et Exécution

### Compilation
Pour compiler le projet, vous pouvez utiliser la commande suivante dans le répertoire du projet :

```bash
javac -d out -sourcepath src src/Main.java src/ValidateCert.java
```

### Exécution
Pour exécuter le projet, utilisez la commande suivante (en adaptant les chemins d’accès) :

- **Validation d’un certificat unique :**

```bash
java -cp out Main validate-cert -format PEM "chemin/vers/le/certificat.pem"
```

- **Validation d’une chaîne de certificats :**

```bash
java -cp out Main validate-cert-chain -format PEM "chemin/vers/RootCert.pem" "chemin/vers/IntermediateCert.pem" "chemin/vers/LeafCert.pem"
```

---

## Utilisation

Le projet offre deux modes de validation :

1. **validate-cert**  
   Permet de vérifier un seul certificat, considéré comme un Root CA s’il est auto-signé.  
   Exemple :

   ```bash
   java -cp out Main validate-cert -format PEM "C:\chemin\vers\certificat.pem"
   ```

2. **validate-cert-chain**  
   Permet de vérifier une chaîne complète de certificats en respectant l'ordre suivant :  
   **Root CA → Intermediate CA → Leaf Cert**  
   La fonction récursive vérifie que chaque certificat est signé par son émetteur et que les extensions Key Usage et Basic Constraints sont conformes à leur rôle.
   Exemple :

   ```bash
   java -cp out Main validate-cert-chain -format PEM "C:\chemin\vers\RootCert.pem" "C:\chemin\vers\IntermediateCert.pem" "C:\chemin\vers\LeafCert.pem"
   ```

---


