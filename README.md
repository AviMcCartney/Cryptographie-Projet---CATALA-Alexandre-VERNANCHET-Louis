# Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis
Projet cryptographie ISEN4 cybersécurité

Ce projet a pour but de valider des certificats X.509 en Java, en s’appuyant sur diverses étapes de vérification (analyse des propriétés du certificat, vérification de la signature, contrôle de révocation via OCSP ou CRL, etc.). Il fournit également des fonctionnalités d’affichage des informations sur le ou les certificats manipulés, ainsi qu’un système de cache pour optimiser la récupération des listes de révocation (CRL).

## Table des Matières
1. [Contexte](#contexte)
2. [Fonctionnalités Principales](#fonctionnalités-principales)
3. [Arborescence du Projet](#arborescence-du-projet)
4. [Description des Classes](#description-des-classes)
5. [Compilation et Exécution](#compilation-et-exécution)
6. [Utilisation](#utilisation)
7. [Exemples d’Exécution](#exemples-dexécution)

---

## Contexte

Ce projet fait partie d’un **projet de cryptographie** visant à manipuler et valider des certificats X.509 en Java. L’application prend en charge la vérification de certificats uniques (leaf) ou de chaînes de certificats, ainsi que la vérification de la révocation via **OCSP** et **CRL**. Elle utilise la bibliothèque [BouncyCastle](https://www.bouncycastle.org/) pour certaines opérations cryptographiques (ECDSA, parsing ASN.1, etc.).

---

## Fonctionnalités Principales

- **Validation de certificat unique** : vérifie si un certificat est valide (dates de validité, signature, extensions).
- **Validation de chaîne de certificats** : s’assure de la bonne signature de chaque certificat par son émetteur, depuis le leaf jusqu’à la racine.
- **Vérification de la révocation** :
  - **OCSP** : construction et envoi de requêtes OCSP vers un serveur, si l’URL OCSP est disponible dans le certificat.
  - **CRL** : téléchargement et mise en cache de la CRL, vérification que le certificat n’y figure pas comme révoqué.
- **Informations détaillées** : affichage des informations sur chaque certificat (sujet, émetteur, date de validité, numéro de série, etc.).
- **Gestion de l’affichage** : messages d’erreur, détails sur la progression des vérifications, etc.

---

## Arborescence du Projet

Voici une vue d’ensemble (fichiers principaux et packages) :

```
org/
└── example/
    ├── Main.java                         (Point d’entrée du programme)                 citeturn0file0
    └── Certificats/
        ├── Affichage/
        │   └── ManageAffichage.java      (Méthodes d'affichage et aide CLI)            citeturn0file1
        ├── Utiles/
        │   ├── utilitaire.java           (Fonctions utilitaires diverses)              citeturn0file2
        │   ├── OCSPManager.java          (Gère la logique de requête OCSP)             citeturn0file3
        │   └── CRLManager.java           (Gère la logique de téléchargement CRL)       citeturn0file4
        └── Validation/
            ├── ValidationCertificat.java (Processus de validation : signature, CRL...) citeturn0file5
            ├── VerifierExtension.java    (Vérif. KeyUsage, dates, BasicConstraints)    citeturn0file6
            └── VerifierSignature.java    (Vérif. signature RSA & ECDSA)                citeturn0file7
```
---

## Description des Classes

### Main.java
Point d’entrée du programme. Il parse les arguments de la ligne de commande, détermine s’il faut valider un certificat unique ou une chaîne de certificats, puis s’appuie sur les fonctions de chargement et de validation.  


### ManageAffichage.java
- Gère l’affichage des informations sur les certificats (sujet, émetteur, validité, etc.).
- Fournit une fonction d’aide pour l’utilisation en ligne de commande.
- Vérifie de manière basique la validité de la date du certificat.  

### utilitaire.java
- Contient quelques utilitaires génériques, par exemple pour vérifier si une chaîne de certificats est vide ou nulle.  

### OCSPManager.java
- Extrait l’URL OCSP depuis l’extension “Authority Information Access” d’un certificat.
- Construit et envoie la requête OCSP (POST) vers le serveur OCSP.
- Analyse la réponse pour déterminer si le certificat est révoqué.  

### CRLManager.java
- Extrait l’URL CRL depuis l’extension “CRL Distribution Points” d’un certificat.
- Télécharge et met en cache la CRL (fichier .crl), afin d’éviter des téléchargements successifs inutiles.
- Vérifie, via la CRL, si un certificat est listé comme révoqué.  

### ValidationCertificat.java
- Orchestre la validation globale :
  - Vérification des propriétés du certificat (KeyUsage, BasicConstraints).
  - Vérification de la révocation (OCSP, si disponible, sinon CRL).
- Fournit aussi une méthode `verifierSignature()` pour déléguer aux méthodes RSA ou ECDSA.  

### VerifierExtension.java
- Vérifie les **extensions** X.509 essentielles : KeyUsage, BasicConstraints, dates de validité.  

### VerifierSignature.java
- Vérifie la signature RSA “manuellement” (calcul de la signature avec l’exposant public, comparaison du hash).
- Vérifie la signature ECDSA (extraction de r et s, usage de BouncyCastle pour la courbe, etc.).
- Permet aussi de vérifier qu’un certificat racine est bien auto-signé.  

---

## Compilation et Exécution

Le projet est codé en Java et utilise la bibliothèque **BouncyCastle**. Vous aurez donc besoin :

- **Java 8** (ou plus récent).
- Le JAR de BouncyCastle (ex. `bcprov-jdk15on-*.jar`) dans le classpath.

### Exemple de compilation (ligne de commande) :

```bash
# 1) Placer bcprov-jdkXX-XXX.jar dans le dossier lib/ par exemple.
# 2) Compiler :
javac -cp .:lib/bcprov-jdk15on-*.jar org/example/**/*.java
```

### Exemple d’exécution :

```bash
java -cp .:lib/bcprov-jdk15on-*.jar org.example.Main validate-cert -format PEM moncert.pem
```

> Adaptez bien sûr les chemins selon votre configuration.

---

## Utilisation

Deux commandes principales sont gérées :

1. **Validation d’un certificat unique**  
   ```
   validate-cert -format DER|PEM <fichier_certificat>
   ```
   - Vérifie la validité (dates, signature), l’affiche dans la console, puis effectue d’éventuelles vérifications (extensions, etc.).

2. **Validation d’une chaîne de certificats**  
   ```
   validate-cert-chain -format DER|PEM <certificatRoot> <certificat2> ... <certificatN>
   ```
   - Charge et valide la chaîne de certificats, depuis le **leaf** (dernier argument) jusqu’à la **racine** (premier argument).
   - Affiche les informations sur chaque certificat et effectue des contrôles (signature, extensions, révocation, etc.).

Pour plus de détails, lancez le programme sans arguments ou de manière incorrecte pour voir l’aide.  
citeturn0file1

---

## Exemples d’Exécution

1. **Validation d’un certificat unique en PEM**  
   ```bash
   java -cp .:lib/bcprov-jdk15on-*.jar org.example.Main validate-cert -format PEM moncert.pem
   ```
   Résultat attendu :  
   - Affichage des informations basiques du certificat (subject, issuer, dates).
   - Vérification de la validité des dates et de la signature.
   - Vérification des extensions (KeyUsage, BasicConstraints s’il y a lieu).

2. **Validation d’une chaîne en DER**  
   ```bash
   java -cp .:lib/bcprov-jdk15on-*.jar org.example.Main validate-cert-chain -format DER rootCert.der intermCert.der leafCert.der
   ```
   Résultat attendu :  
   - Vérification de chaque certificat dans la console (subject, issuer…).
   - Vérification de la signature de chaque certificat par son émetteur.
   - Vérification de la révocation via OCSP (si l’URL est disponible), sinon via CRL.

---
