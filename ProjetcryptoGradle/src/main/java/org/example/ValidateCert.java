package org.example;

//Importation des classes nécessaires
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.*;
import java.security.Signature;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class ValidateCert {

    //Ajout du fournisseur BouncyCastle
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Charge un certificat X.509 au format DER depuis un fichier
     * @param filePath Chemin du fichier contenant le certificat au format DER
     * @return Un objet x509 Certificate ou une exception en cas d'erreur
     * @throws Exception S'il y a une erreur lors de la lecture du fichier
     */
    public static X509Certificate affichage_DER(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(filePath)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    /**
     * Charge un certificat X.509 au format PEM depuis un fichier
     * @param filePath Chemin du fichier contenant le certificat au format PEM
     * @return Un objet x509 Certificate ou une exception en cas d'erreur
     * @throws Exception S'il y a une erreur lors de la lecture du fichier
     */
    public static X509Certificate affichage_PEM(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)));
        String base64Cert = pemContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(base64Cert);
        try (InputStream inStream = new ByteArrayInputStream(decoded)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    /**
     * Vérifie si un certificat est auto-signé en utilisant sa propre clé publique
     * Cette méthode sert uniquement dans la partie 1 du projet et est remplacé par verifiersignatureRSA/ECDSA
     * @param cert Certificat X.509 à vérifier
     * @see java.security.cert.X509Certificate
     * {@link X509Certificate#verify(PublicKey) Fonctionne sur les certificats auto-signés car ils sont signés avec leur propre clé privée et peuvent être validés avec leur clé
     * publique}
     * @return true si le certificat est auto-signé, false sinon
     */
    public static boolean verifierSignature(X509Certificate cert) {
        try {
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            return true;
        } catch (Exception e) {
            System.err.println("Échec de la vérification de la signature: " + e.getMessage());
            return false;
        }
    }

    /**
     * Vérifie les usages de clé (KeyUsage) d'une chaîne de certificats
     * @param certChain Liste des certificats à vérifier
     * @return true si tous les certificats respectent les usages clés attendus, false sinon
     */
    public static boolean verifierKeyUsage(List<X509Certificate> certChain) {
        if (IsChainNull(certChain)) {
            return false;
        }

        //Si on a un seul certificat, c'est un root
        boolean isSingleRoot = (certChain.size() == 1);

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);
            boolean[] keyUsage = cert.getKeyUsage();

            //Si l'extension KeyUsage n'est pas définie, on considère qu'il n'y a pas de restriction
            if (keyUsage == null) {
                System.out.println("Aucun KeyUsage spécifié, le certificat est peut-être valide.");
                continue;
            }

            boolean hasRequiredUsage = false;
            for (int j = 0; j < keyUsage.length; j++) {
                if (keyUsage[j]) {
                    //Vérification selon le type de certificat
                    if (!isSingleRoot && i == 0 && j == 0) hasRequiredUsage = true; // Leaf → Digital Signature
                    if ((isSingleRoot || i > 0) && j == 5) hasRequiredUsage = true; // Root ou intermédiaire → Certificate Signing
                }
            }

            //Vérification finale en fonction du type de certificat
            if (!isSingleRoot && i == 0 && !hasRequiredUsage) {
                System.err.println("Le certificat Leaf doit avoir 'Digital Signature'.");
                return false;
            }
            if ((isSingleRoot || i > 0) && !hasRequiredUsage) {
                System.err.println("Le certificat Intermédiaire/Root doit avoir 'Certificate Signing'.");
                return false;
            }
        }
        return true;
    }

    /**
     * Vérifie si un certificat est toujours valide en termes de date
     * @param cert Certificat à vérifier
     * {@link X509Certificate#checkValidity() prend la date de début et de fin de validité et les compare à la date actuelle}
     * @return true si la date est valide, false sinon
     */
    public static boolean verifierDate(X509Certificate cert){
        try{
            cert.checkValidity();
            return true;
        } catch (Exception e) {
            System.err.println("Échec de la vérification de la date: " + e.getMessage());
            return false;
        }
    }

    /**
     * Vérifie l'algorithme de signature ainsi que la validité de la signature
     * Cette fonction était utile pour répondre à la question six de la première partie.
     * Maintenant, il est plus intéressant d'utiliser verifiersignatureRSA/ECDSA
     * @param cert Le certificat à vérifier
     * {@link X509Certificate#getSigAlgName() Récupération de l'algorithme de signature utilisé}
     * {@link X509Certificate#getSignature() Récupération de la signature}
     * {@link X509Certificate#getPublicKey() Récupération de la clé publique}
     * {@link java.security.Signature#getInstance(String) Création d'un objet Signature à partir de l'algorithme de signature}
     * {@link java.security.Signature#initVerify(PublicKey) Initialisation de l'objet}
     * {@link java.security.Signature#update(byte) Mise à jour de l'objet avec la structure du certificat}
     * {@link X509Certificate#getTBSCertificate() Renvoie toutes les informations du certificat sauf la signature}
     * {@link java.security.Signature#verify(byte[]) Vérification de la signature en comparant les données signées avec la signature extraite}
     */
    public static void verifierAlgorithmeEtSignature(X509Certificate cert) {
        try {
            String algo = cert.getSigAlgName();
            byte[] signature = cert.getSignature();
            PublicKey publicKey = cert.getPublicKey();
            Signature sig = Signature.getInstance(algo);
            sig.initVerify(publicKey);
            sig.update(cert.getTBSCertificate());
            boolean verified = sig.verify(signature);
            System.out.println("Algorithme de signature: " + algo);
            System.out.println("Signature vérifiée: " + (verified ? "Valide" : "Invalide"));
        } catch (Exception e) {
            System.err.println("Échec de la vérification de l'algorithme et de la signature: " + e.getMessage());
        }
    }

    /**
     * Affiche les informations générales d'un certificat X.509
     * @param cert Certificat X.509 dont on veut afficher les informations
     */
    public static void afficherInfosCertificat(X509Certificate cert) {
        System.out.println("=== Informations du Certificat ===");
        System.out.println("Sujet : " + cert.getSubjectX500Principal());
        System.out.println("Émetteur : " + cert.getIssuerX500Principal());
        System.out.println("Date de début de validité : " + cert.getNotBefore());
        System.out.println("Date de fin de validité : " + cert.getNotAfter());
        System.out.println("Numéro de série : " + cert.getSerialNumber());
    }

    /**
     * Vérifie la validité d'une chaîne de certificats en s'assurant que chaque certificat est bien signé par son émetteur
     * @param chain Liste des certificats représentant la chaîne
     * @return true si la chaîne est valide, false sinon
     */
    public static boolean verifierChaineCertificats(List<X509Certificate> chain) {
        if (IsChainNull(chain)) {
            return false;
        }

        //Vérification récursive en partant du Leaf
        return verifierRecursive(chain, chain.size() - 1);
    }

    /**
     * Vérifie récursivement la validité de la chaîne de certificats
     * @param chain Liste des certificats
     * @param index Position actuelle dans la liste
     * @return true si la chaîne est valide, false sinon
     */
    private static boolean verifierRecursive(List<X509Certificate> chain, int index) {
        if (index == 0) {
            X509Certificate rootCert = chain.getFirst();
            try {
                rootCert.verify(rootCert.getPublicKey());
                System.out.println("Le certificat racine " + rootCert.getSubjectX500Principal() + " est auto-signé et valide.");
                return true;
            } catch (Exception e) {
                System.err.println("Erreur : Le certificat racine " + rootCert.getSubjectX500Principal() + " n'est pas auto-signé correctement.");
                return false;
            }
        }

        //Vérification de la signature du certificat courant par le suivant (on remonte)
        X509Certificate cert = chain.get(index);
        X509Certificate issuerCert = chain.get(index - 1);

        try {
            cert.verify(issuerCert.getPublicKey());
            System.out.println("Le certificat " + cert.getSubjectX500Principal() + " est bien signé par " + issuerCert.getSubjectX500Principal());
        } catch (Exception e) {
            System.err.println("Erreur : Le certificat " + cert.getSubjectX500Principal() + " n'est pas signé par " + issuerCert.getSubjectX500Principal());
            return false;
        }

        //Vérification de la correspondance Sujet / Émetteur
        if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
            System.err.println("Erreur : L'émetteur du certificat " + cert.getIssuerX500Principal() + " ne correspond pas au sujet du certificat parent " + issuerCert.getSubjectX500Principal());
            return false;
        }

        //Vérification récursive sur le certificat précédent
        return verifierRecursive(chain, index - 1);
    }

    /**
     * Vérifie la signature RSA d'une chaîne de certificats en utilisant BigInteger
     * @param certChain Liste des certificats à vérifier
     * @return true si toutes les signatures sont valides, false sinon
     */
    public static boolean verifierSignatureRSA_BigInteger(List<X509Certificate> certChain) {
        try {
            if (IsChainNull(certChain)) {
                return false;
            }

            Collections.reverse(certChain);

            for (int i = 0; i < certChain.size(); i++) {
                X509Certificate cert = certChain.get(i);
                PublicKey issuerPublicKey;

                if (i < certChain.size() - 1) {
                    //Utiliser la clé publique du certificat émetteur
                    issuerPublicKey = certChain.get(i + 1).getPublicKey();
                } else {
                    //Si c'est le Root CA, il est auto-signé
                    issuerPublicKey = cert.getPublicKey();
                }

                if (!(issuerPublicKey instanceof RSAPublicKey rsaPublicKey)) {
                    System.err.println("Erreur : La clé publique du certificat " + cert.getSubjectX500Principal() + " n'est pas RSA.");
                    return false;
                }

                BigInteger decryptedMessage = getBigInteger(rsaPublicKey, cert);

                //Détecter l'algorithme de hachage du certificat
                String sigAlg = cert.getSigAlgName().toUpperCase();
                String hashAlgorithm;
                if (sigAlg.contains("SHA256")) {
                    hashAlgorithm = "SHA-256";
                } else if (sigAlg.contains("SHA384")) {
                    hashAlgorithm = "SHA-384";
                } else if (sigAlg.contains("SHA512")) {
                    hashAlgorithm = "SHA-512";
                } else {
                    System.err.println("Algorithme de hachage non supporté : " + sigAlg);
                    return false;
                }

                //Vérification du hash de la signature
                MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
                byte[] tbsCertificate = cert.getTBSCertificate();
                byte[] expectedHash = digest.digest(tbsCertificate);

                //Comparaison avec la signature déchiffrée
                byte[] decryptedBytes = decryptedMessage.toByteArray();
                byte[] extractedHash = Arrays.copyOfRange(decryptedBytes, decryptedBytes.length - expectedHash.length, decryptedBytes.length);

                if (!Arrays.equals(extractedHash, expectedHash)) {
                    System.err.println("Échec de la vérification de signature RSA pour " + cert.getSubjectX500Principal());
                    return false;
                }

                System.out.println("Vérification de signature RSA réussie pour " + cert.getSubjectX500Principal());
            }

            return true;
        } catch (Exception e) {
            System.err.println("Erreur lors de la vérification de signature RSA : " + e.getMessage());
            return false;
        }
    }

    /**
     * Effectue le déchiffrement de la signature RSA d'un certificat
     * @param rsaPublicKey Clé publique RSA utilisée pour le déchiffrement
     * @param cert Certificat dont on veut déchiffrer la signature
     * @return La valeur BigInteger de la signature déchiffrée
     */
    private static BigInteger getBigInteger(RSAPublicKey rsaPublicKey, X509Certificate cert) {
        BigInteger modulus = rsaPublicKey.getModulus();  // N (modulus)
        BigInteger exponent = rsaPublicKey.getPublicExponent(); // e (exponent)

        // Récupérer la signature chiffrée
        byte[] signatureBytes = cert.getSignature();
        BigInteger signature = new BigInteger(1, signatureBytes); // S (signature chiffrée)

        // Effectuer le calcul de la signature RSA manuellement : M = S^e mod N
        return signature.modPow(exponent, modulus);
    }

    /**
     * Vérifie la signature ECDSA d'une chaîne de certificats
     * Cette méthode utilise la bibliothèque BouncyCastle pour effectuer la vérification de la signature
     * ECDSA de chaque certificat avec la clé publique de son émetteur
     * @param certChain Liste des certificats à vérifier
     * @return true si toutes les signatures sont valides, false sinon
     */
    public static boolean verifierSignatureECDSA(List<X509Certificate> certChain) {
        try {
            //Ajoute BouncyCastle comme fournisseur de sécurité
            Security.addProvider(new BouncyCastleProvider());

            if (IsChainNull(certChain)) {
                return false;
            }

            // Inverser la liste pour que la validation commence par le certificat leaf
            Collections.reverse(certChain);

            for (int i = 0; i < certChain.size(); i++) {
                X509Certificate cert = certChain.get(i);
                PublicKey issuerPublicKey;

                if (i < certChain.size() - 1) {
                    //Si ce n'est pas le certificat racine, utiliser la clé publique du certificat suivant
                    issuerPublicKey = certChain.get(i + 1).getPublicKey();
                } else {
                    //Si c'est le certificat racine, utiliser sa propre clé publique
                    issuerPublicKey = cert.getPublicKey();
                }

                //Vérifier si la clé publique est bien ECDSA
                if (!(issuerPublicKey instanceof ECPublicKey)) {
                    try {
                        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                        issuerPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(issuerPublicKey.getEncoded()));
                    } catch (Exception ex) {
                        System.err.println("Échec de la conversion de la clé en ECPublicKey : " + ex.getMessage());
                        return false;
                    }
                }

                //Extraction des paramètres de la courbe elliptique
                ECPublicKey ecPublicKey = (ECPublicKey) issuerPublicKey;
                ECParameterSpec ecSpec = ecPublicKey.getParameters();
                ECPoint Q = ecPublicKey.getQ();

                //Identification de la courbe utilisée
                X9ECParameters ecParams = null;
                for (Enumeration<?> names = CustomNamedCurves.getNames(); names.hasMoreElements();) {
                    String name = (String) names.nextElement();
                    X9ECParameters params = CustomNamedCurves.getByName(name);
                    if (params != null && params.getCurve().equals(ecSpec.getCurve())) {
                        ecParams = params;
                        break;
                    }
                }

                if (ecParams == null) {
                    System.err.println("Impossible d'identifier la courbe elliptique pour " + cert.getSubjectX500Principal());
                    return false;
                }

                //Définition des paramètres de domaine pour ECDSA
                ECDomainParameters domainParams = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

                //Récupérer l'algorithme de signature
                String sigAlg = cert.getSigAlgName();
                String hashAlgorithm;
                if (sigAlg.contains("SHA256")) {
                    hashAlgorithm = "SHA-256";
                } else if (sigAlg.contains("SHA384")) {
                    hashAlgorithm = "SHA-384";
                } else if (sigAlg.contains("SHA512")) {
                    hashAlgorithm = "SHA-512";
                } else {
                    System.err.println("Algorithme de hachage non supporté : " + sigAlg);
                    return false;
                }

                //Extraire la signature du certificat
                byte[] signatureBytes = cert.getSignature();
                ASN1InputStream asn1InputStream = new ASN1InputStream(signatureBytes);
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
                asn1InputStream.close();
                BigInteger r = ((ASN1Integer) asn1Sequence.getObjectAt(0)).getValue();
                BigInteger s = ((ASN1Integer) asn1Sequence.getObjectAt(1)).getValue();

                //Calculer le hachage du certificat avec l'algorithme correspondant
                MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
                byte[] hash = digest.digest(cert.getTBSCertificate());
                BigInteger e = new BigInteger(1, hash);

                //Calculer w = s*pow(-1) mod n
                BigInteger w = s.modInverse(domainParams.getN());
                BigInteger u1 = e.multiply(w).mod(domainParams.getN());
                BigInteger u2 = r.multiply(w).mod(domainParams.getN());

                //Calculer P = u1 * G + u2 * Q
                ECPoint P = domainParams.getG().multiply(u1).add(Q.multiply(u2)).normalize();

                //Vérification du point résultant
                if (P.isInfinity()) {
                    System.err.println("Échec de la vérification : Point à l'infini pour " + cert.getSubjectX500Principal());
                    return false;
                }

                //Comparaison de r avec la coordonnée x de P modulo n
                if (!P.getXCoord().toBigInteger().mod(domainParams.getN()).equals(r)) {
                    System.err.println("Échec de la vérification de signature ECDSA pour " + cert.getSubjectX500Principal());
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            System.err.println("Erreur lors de la vérification de signature ECDSA : " + e.getMessage());
            return false;
        }
    }

    /**
     * Vérifie la validité des Basic Constraints pour une chaîne de certificats
     * @param certChain Liste des certificats à vérifier
     * {@link X509Certificate#getBasicConstraints() Récupération de l'extension BasicConstraint}
     * @return true si les Basic Constraints sont respectées, false sinon
     */
    public static boolean verifierBasicConstraints(List<X509Certificate> certChain) {

        if (IsChainNull(certChain)) {
            return false;
        }

        boolean isSingleRoot = (certChain.size() == 1);

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);

            // Déterminer le rôle du certificat
            boolean isRoot = isSingleRoot || i == certChain.size() - 1;
            boolean isLeaf = !isSingleRoot && i == 0;
            boolean isLastInterm = (i == certChain.size() - 2);

            int basicConstraints = cert.getBasicConstraints();

            if (isLeaf) {
                // Vérification que le certificat Leaf n'est pas un CA
                if (basicConstraints != -1) {
                    System.err.println("Erreur : Le certificat Leaf ne doit pas être un CA.");
                    return false;
                }
            } else {
                // Vérification que le certificat est un CA
                if (basicConstraints == -1) {
                    System.err.println("Erreur : Le certificat " + cert.getSubjectX500Principal() +
                            " n'est pas un CA, mais il est dans la chaîne de certification.");
                    return false;
                }

                // Vérification du pathLenConstraint pour les intermédiaires
                int expectedMaxIntermediates = certChain.size() - (i + 1);

                if (!isRoot && !isLastInterm && basicConstraints >= 0 && basicConstraints < expectedMaxIntermediates) {
                    System.err.println("Erreur : Le certificat " + cert.getSubjectX500Principal() +
                            " a un pathLenConstraint trop faible (" + basicConstraints + "), il ne peut pas signer autant d'intermédiaires.");
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Vérifie si une liste de certificats est vide ou nulle
     * @param chain Liste de certificats
     * @return true si la liste est vide ou nulle, false sinon
     */
    public static boolean IsChainNull (List<X509Certificate> chain){
        if (chain == null || chain.isEmpty()) {
            System.err.println("Erreur : Liste de certificats vide ou nulle.");
            return true;
        }
        return false;
    }

    /**
     * Télécharge la CRL depuis l'URL extraite du certificat
     * @param cert Certificat dont on veut vérifier la révocation
     * @return Un objet X509CRL ou null en cas d'échec
     */
    public static X509CRL telechargerCRL(X509Certificate cert) {
        try {
            String crlUrl = extraireCRLDistributionPoint(cert);
            if (crlUrl == null) {
                System.err.println("Aucune URL CRL trouvée pour le certificat : " + cert.getSubjectX500Principal());
                return null;
            }

            try (InputStream crlStream = new URI(crlUrl).toURL().openStream()) {

                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                return (X509CRL) cf.generateCRL(crlStream);
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du téléchargement de la CRL : " + e.getMessage());
            return null;
        }
    }


    /**
     * Extrait l'URL de la CRL depuis le certificat
     * @param cert Certificat contenant l'extension CRL Distribution Points
     * @return L'URL de la CRL ou null en cas d'échec
     */
    public static String extraireCRLDistributionPoint(X509Certificate cert) {
        try {
            byte[] crlBytes = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crlBytes == null) {
                System.err.println("Aucune extension CRL trouvée");
                return null;
            }

            // Décodage ASN.1
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(crlBytes))) {
                ASN1OctetString octetString = ASN1OctetString.getInstance(asn1InputStream.readObject());
                try (ASN1InputStream asn1Stream2 = new ASN1InputStream(new ByteArrayInputStream(octetString.getOctets()))) {
                    CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Stream2.readObject());

                    for (DistributionPoint dp : crlDistPoint.getDistributionPoints()) {
                        DistributionPointName dpn = dp.getDistributionPoint();
                        if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                            for (GeneralName gn : GeneralNames.getInstance(dpn.getName()).getNames()) {
                                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                    return gn.getName().toString();
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de l'extraction de l'URL de la CRL : " + e.getMessage());
        }
        return null;
    }

    /**
     * Vérifie si un certificat est révoqué en téléchargeant et en validant sa CRL
     * @param cert Certificat à vérifier
     * @param possibleIssuers Liste des certificats émetteurs possibles
     * @return true si le certificat est révoqué, false sinon
     */
    public static boolean verifierRevocationAvecCRL(X509Certificate cert, List<X509Certificate> possibleIssuers) {
        try {
            // Vérifier si c'est un Root CA
            if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                System.out.println("Le certificat " + cert.getSubjectX500Principal() + " est un Root CA. Vérification CRL ignorée.");
                return false;
            }

            X509CRL crl = telechargerCRL(cert);
            if (crl == null) {
                System.err.println("Impossible de récupérer la CRL pour la vérification.");
                return false;
            }

            X509Certificate crlIssuerCert = null;
            for (X509Certificate issuer : possibleIssuers) {
                if (crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                    crlIssuerCert = issuer;
                    break;
                }
            }

            if (crlIssuerCert == null) {
                System.err.println("Aucun certificat trouvé correspondant à l’émetteur de la CRL");
                return false;
            }

            // Vérification de la signature de la CRL
            try {
                crl.verify(crlIssuerCert.getPublicKey());
            } catch (Exception e) {
                System.err.println("Erreur de vérification de la signature de la CRL : " + e.getMessage());
                return false;
            }

            // Vérification de la révocation du certificat
            X509CRLEntry crlEntry = crl.getRevokedCertificate(cert.getSerialNumber());
            return crlEntry != null;

        } catch (Exception e) {
            System.err.println("Erreur lors de la vérification de révocation : " + e.getMessage());
            return false;
        }
    }

    /**
     * Vérifie si un certificat est révoqué via OCSP
     * @param cert Le certificat à vérifier
     * @param issuerCert Le certificat de l'autorité de certification émettrice
     * @return true si le certificat est révoqué, false sinon
     */
    public static boolean verifierRevocationOCSP(X509Certificate cert, X509Certificate issuerCert) {
        try {
            //Récupérer l'URL OCSP depuis le certificat
            Optional<String> ocspUrlOpt = extraireOCSPUrl(cert);
            if (ocspUrlOpt.isEmpty()) {
                System.err.println("Aucune URL OCSP trouvée pour " + cert.getSubjectX500Principal());
                return false;
            }
            String ocspUrl = ocspUrlOpt.get();

            //Construire et envoyer la requête OCSP
            return Optional.ofNullable(creerRequeteOCSP(cert, issuerCert))
                    .map(req -> envoyerRequeteOCSP(ocspUrl, req))
                    .orElse(false);

        } catch (Exception e) {
            System.err.println("Erreur OCSP : " + e.getMessage());
            return false;
        }
    }

    /**
     * Extrait l'URL OCSP depuis les extensions d'un certificat X.509
     * @param cert Le certificat X.509 contenant l'extension Authority Information Access
     * @return Un {@code Optional<String>} contenant l'URL OCSP si disponible, sinon {@code Optional.empty()}
     */
    public static Optional<String> extraireOCSPUrl(X509Certificate cert) {
        try {
            byte[] ocspExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (ocspExtensionValue == null) return Optional.empty();

            try (ASN1InputStream asn1Input = new ASN1InputStream(new ByteArrayInputStream(ocspExtensionValue))) {
                ASN1Primitive obj = asn1Input.readObject();
                ASN1OctetString octetString = ASN1OctetString.getInstance(obj);

                try (ASN1InputStream asn1Stream = new ASN1InputStream(octetString.getOctets())) {
                    AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(asn1Stream.readObject());

                    for (AccessDescription accessDesc : aia.getAccessDescriptions()) {
                        if (AccessDescription.id_ad_ocsp.equals(accessDesc.getAccessMethod())) {
                            GeneralName name = accessDesc.getAccessLocation();
                            if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                return Optional.of(name.getName().toString());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur extraction URL OCSP : " + e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Génère une requête OCSP pour vérifier le statut de révocation d'un certificat
     * @param cert Le certificat dont le statut doit être vérifié
     * @param issuerCert Le certificat de l'autorité de certification émettrice
     * @return Un tableau de bytes contenant la requête OCSP encodée, ou {@code null} en cas d'erreur
     */
    private static byte[] creerRequeteOCSP(X509Certificate cert, X509Certificate issuerCert) {
        try {
            //Création d'un calculateur de hachage SHA-1 requis pour OCSP
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                    .build().get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1"));

            //Génération de l'ID du certificat à vérifier
            CertificateID certID = new CertificateID(digestCalculator,
                    new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

            //Création de la requête OCSP
            OCSPReq ocspRequest = new OCSPReqBuilder().addRequest(certID).build();
            return ocspRequest.getEncoded();

        } catch (Exception e) {
            System.err.println("Erreur création requête OCSP : " + e.getMessage());
            return null;
        }
    }

    /**
     * Envoie une requête OCSP à un serveur OCSP et analyse la réponse
     * @param ocspUrl L'URL du serveur OCSP
     * @param ocspRequestBytes La requête OCSP encodée
     * @return true si le certificat est révoqué, false sinon
     */
    private static boolean envoyerRequeteOCSP(String ocspUrl, byte[] ocspRequestBytes) {
        try {
            URL url = new URI(ocspUrl).toURL();
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);

            // Envoi de la requête OCSP
            try (OutputStream os = con.getOutputStream()) {
                os.write(ocspRequestBytes);
            }

            // Vérification du code HTTP
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                System.err.println("Erreur OCSP HTTP : " + con.getResponseCode());
                return false;
            }

            // Lecture et analyse de la réponse OCSP
            try (InputStream is = con.getInputStream();
                 ASN1InputStream asn1InputStream = new ASN1InputStream(is)) {

                OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(asn1InputStream.readObject()));
                if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                    System.err.println("Réponse OCSP invalide, code: " + ocspResp.getStatus());
                    return false;
                }

                BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
                if (basicResp == null) {
                    System.err.println("Impossible d'extraire la réponse OCSP.");
                    return false;
                }

                // Vérification du statut du certificat
                SingleResp[] responses = basicResp.getResponses();
                if (responses.length > 0) {
                    CertificateStatus certStatus = responses[0].getCertStatus();
                    return certStatus != CertificateStatus.GOOD;
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur envoi requête OCSP : " + e.getMessage());
        }
        return false;
    }
}
