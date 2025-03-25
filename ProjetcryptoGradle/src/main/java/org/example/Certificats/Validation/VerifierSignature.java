package org.example.Certificats.Validation;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static org.example.Certificats.Utiles.utilitaire.IsChainNull;

public class VerifierSignature {
    /**
     * Vérifie si un certificat est auto-signé en utilisant sa propre clé publique
     * Cette méthode sert uniquement dans la partie 1 du projet et est remplacé par verifiersignatureRSA/ECDSA
     * @param cert Certificat X.509 à vérifier
     * @see java.security.cert.X509Certificate
     * {@link X509Certificate#verify(PublicKey) Fonctionne sur les certificats auto-signés car ils sont signés avec leur propre clé privée et peuvent être validés avec leur clé
     * publique}
     * @return true si le certificat est auto-signé, false sinon
     */
    private static boolean verifierSignature(X509Certificate cert) {
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
    private static void verifierAlgorithmeEtSignature(X509Certificate cert) {
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
}
