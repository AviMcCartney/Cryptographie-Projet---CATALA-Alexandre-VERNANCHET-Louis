package org.example;

//Importation des classes nécessaires
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;




public class ValidateCert {

    /**
     *  Fonction qui charge un certificat X.509 au format DER depuis un fichier donné
     * @param filePath Chemin du fichier contenant le certificat en format DER
     * @return Un objet x509 Certificate
     * @throws Exception S'il y a une erreur à la lecture du fichier
     */
    public static X509Certificate affichage_DER(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(filePath)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    /**
     * Fonction qui charge un certificat X.509 au format PEM depuis un fichier donné
     * @param filePath Chemin du fichier contenant le certificat au format PEM
     * @return Un objet x509 Certificate
     * @throws Exception S'il y a une erreur à la lecture du fichier
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
     * Fonction permettant de vérifier la signature d'un certificat en utilisant sa propre clé publique
     * @param cert Certificat X509 à vérifier
     * @see java.security.cert.X509Certificate
     * {@link X509Certificate#verify(PublicKey) Fonctionne sur les certificats auto-signés car ils sont signés avec leur propre clé privée et peuvent être validés avec leur clé
     * publique}
     * @return true si la signature est valide, false avec un message d'erreur sinon
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
     * Fonction qui affiche les usages de clé qui sont définis dans un certificat x509
     * @param cert Le certificat dont les usages de clé doivent être vérifiés
     * {@link X509Certificate#getKeyUsage() Récupère ce qui est écrit dans l'extension keyusage}
     */
    public static void verifierKeyUsage(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            System.out.println("Key Usage:");
            String[] usages = {"Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only", "Decipher Only"};
            for (int i = 0; i < keyUsage.length; i++) {
                if (keyUsage[i]) {
                    System.out.println("✔ " + usages[i]);
                }
            }
        } else {
            System.out.println("Key Usage non spécifié dans le certificat.");
        }
    }

    /**
     * Fonction qui permet la vérification de la date d'expiration du certificat
     * @param cert le certificat x509 à vérifier
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
     * Fonction qui vérifie l'algorithme de signature ainsi que la validité de la signature
     * @param cert Le certificat à analyser
     * {@link X509Certificate#getSigAlgName() récupération de l'algorithme de signature utilisé}
     * {@link X509Certificate#getSignature() récupération de la signature}
     * {@link X509Certificate#getPublicKey() Récupération de la clé publique}
     * {@link java.security.Signature#getInstance(String) Création d'un objet Signature à partir de l'algorithme de signature}
     * {@link java.security.Signature#initVerify(PublicKey) Initialisation de l'objet}
     * {@link java.security.Signature#update(byte) Mise à jour de l'objet avce la structure du certificat}
     * {@link X509Certificate#getTBSCertificate() Renvoie toutes les informations du certificat sauf la signature}
     * {@link java.security.Signature#verify(byte[]) verification de la signature en comparant les données signées avec la signature extraite}
     * {@link java.io.PrintStream#println(char) Affichage des résultats}
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
     *
     * @param cert
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
     *
     * @param chain
     * @return
     */
    public static boolean verifierChaineCertificats(List<X509Certificate> chain) {
        if (chain == null || chain.isEmpty()) {
            System.err.println("❌ Erreur : La chaîne de certificats est vide ou nulle.");
            return false;
        }

        return verifierRecursive(chain, chain.size() - 1); // On commence par le Leaf Cert
    }

    /**
     *
     * @param chain
     * @param index
     * @return
     */
    private static boolean verifierRecursive(List<X509Certificate> chain, int index) {
        // Condition de sortie : On atteint le Root CA (index 0)
        if (index == 0) {
            X509Certificate rootCert = chain.get(0);
            try {
                rootCert.verify(rootCert.getPublicKey());
                System.out.println("✔ Le certificat racine " + rootCert.getSubjectX500Principal() + " est auto-signé et valide.");
                return true;
            } catch (Exception e) {
                System.err.println("❌ Erreur : Le certificat racine " + rootCert.getSubjectX500Principal() + " n'est pas auto-signé correctement.");
                return false;
            }
        }

        // Vérification de la signature du certificat courant par le suivant (on remonte)
        X509Certificate cert = chain.get(index);      // Certificat actuel (Leaf, puis Intermediate)
        X509Certificate issuerCert = chain.get(index - 1);  // Certificat parent (Intermediate, puis Root)

        try {
            cert.verify(issuerCert.getPublicKey());
            System.out.println("✔ Le certificat " + cert.getSubjectX500Principal() + " est bien signé par " + issuerCert.getSubjectX500Principal());
        } catch (Exception e) {
            System.err.println("❌ Erreur : Le certificat " + cert.getSubjectX500Principal() + " n'est pas signé par " + issuerCert.getSubjectX500Principal());
            return false;
        }

        // Vérification de la correspondance Sujet / Émetteur
        if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
            System.err.println("❌ Erreur : L'émetteur du certificat " + cert.getIssuerX500Principal() + " ne correspond pas au sujet du certificat parent " + issuerCert.getSubjectX500Principal());
            return false;
        }

        // Récursion : Vérifier le certificat suivant en remontant
        return verifierRecursive(chain, index - 1);
    }

    /**
     *
     * @param cert
     * @return
     */
    public static boolean verifierSignatureRSA_BigInteger(X509Certificate cert) {
        try {
            // Récupérer la clé publique RSA
            PublicKey publicKey = cert.getPublicKey();
            if (!(publicKey instanceof RSAPublicKey)) {
                System.err.println("❌ Erreur : La clé publique du certificat n'est pas RSA.");
                return false;
            }

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            BigInteger modulus = rsaPublicKey.getModulus();  // N (modulus)
            BigInteger exponent = rsaPublicKey.getPublicExponent(); // e (exponent)

            // Récupérer la signature chiffrée
            byte[] signatureBytes = cert.getSignature();
            BigInteger signature = new BigInteger(1, signatureBytes); // S (signature chiffrée)

            // Effectuer le calcul de la signature RSA manuellement : M = S^e mod N
            BigInteger decryptedMessage = signature.modPow(exponent, modulus);

            // Récupérer le hash attendu du certificat
            MessageDigest digest = MessageDigest.getInstance("SHA-256");  // Algorithme SHA-256
            byte[] tbsCertificate = cert.getTBSCertificate(); // Structure signée du certificat
            byte[] expectedHash = digest.digest(tbsCertificate); // H(M) attendu

            // Extraire les derniers octets de decryptedMessage (car il contient un padding PKCS#1 v1.5)
            byte[] decryptedBytes = decryptedMessage.toByteArray();
            byte[] extractedHash = Arrays.copyOfRange(decryptedBytes, decryptedBytes.length - expectedHash.length, decryptedBytes.length);

            // Comparaison des hashes
            if (Arrays.equals(extractedHash, expectedHash)) {
                System.out.println("✔ Vérification de signature RSA avec BigInteger réussie.");
                return true;
            } else {
                System.err.println("❌ Échec de la vérification de signature RSA avec BigInteger.");
                return false;
            }
        } catch (Exception e) {
            System.err.println("❌ Erreur lors de la vérification de la signature RSA avec BigInteger : " + e.getMessage());
            return false;
        }
    }

    public static boolean verifierSignatureECDSA(List<X509Certificate> certChain) {
        try {
            Security.addProvider(new BouncyCastleProvider());

            if (certChain == null || certChain.isEmpty()) {
                System.err.println("❌ Erreur : Liste de certificats vide ou nulle.");
                return false;
            }

            // 🔄 Inverser la liste pour que la validation commence par le certificat du site
            Collections.reverse(certChain);
            
            for (int i = 0; i < certChain.size(); i++) {
                X509Certificate cert = certChain.get(i);
                PublicKey issuerPublicKey;

                if (i < certChain.size() - 1) {
                    // Si ce n'est pas le certificat racine, utiliser la clé publique du certificat suivant
                    issuerPublicKey = certChain.get(i + 1).getPublicKey();
                } else {
                    // Si c'est le certificat racine, utiliser sa propre clé publique (auto-signé)
                    issuerPublicKey = cert.getPublicKey();
                }

                // Vérifier si la clé publique est bien ECDSA
                if (!(issuerPublicKey instanceof ECPublicKey)) {
                    try {
                        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                        issuerPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(issuerPublicKey.getEncoded()));
                    } catch (Exception ex) {
                        System.err.println("❌ Échec de la conversion de la clé en ECPublicKey : " + ex.getMessage());
                        return false;
                    }
                }

                ECPublicKey ecPublicKey = (ECPublicKey) issuerPublicKey;
                ECParameterSpec ecSpec = ecPublicKey.getParameters();
                ECPoint Q = ecPublicKey.getQ();

                // Trouver la courbe associée
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
                    System.err.println("❌ Impossible d'identifier la courbe elliptique pour " + cert.getSubjectX500Principal());
                    return false;
                }

                ECDomainParameters domainParams = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());

                // Récupérer l'algorithme de signature
                String sigAlg = cert.getSigAlgName();
                String hashAlgorithm;
                if (sigAlg.contains("SHA256")) {
                    hashAlgorithm = "SHA-256";
                } else if (sigAlg.contains("SHA384")) {
                    hashAlgorithm = "SHA-384";
                } else if (sigAlg.contains("SHA512")) {
                    hashAlgorithm = "SHA-512";
                } else {
                    System.err.println("❌ Algorithme de hachage non supporté : " + sigAlg);
                    return false;
                }

                // Extraire la signature du certificat
                byte[] signatureBytes = cert.getSignature();
                ASN1InputStream asn1InputStream = new ASN1InputStream(signatureBytes);
                ASN1Sequence asn1Sequence = (ASN1Sequence) asn1InputStream.readObject();
                asn1InputStream.close();
                BigInteger r = ((ASN1Integer) asn1Sequence.getObjectAt(0)).getValue();
                BigInteger s = ((ASN1Integer) asn1Sequence.getObjectAt(1)).getValue();

                // Calculer le hachage du certificat avec l'algorithme correct
                MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
                byte[] hash = digest.digest(cert.getTBSCertificate());
                BigInteger e = new BigInteger(1, hash);

                // Calculer w = s⁻¹ mod n
                BigInteger w = s.modInverse(domainParams.getN());
                BigInteger u1 = e.multiply(w).mod(domainParams.getN());
                BigInteger u2 = r.multiply(w).mod(domainParams.getN());

                // Calculer P = u1 * G + u2 * Q
                ECPoint P = domainParams.getG().multiply(u1).add(Q.multiply(u2)).normalize();

                if (P.isInfinity()) {
                    System.err.println("❌ Échec de la vérification : Point à l'infini pour " + cert.getSubjectX500Principal());
                    return false;
                }

                if (!P.getXCoord().toBigInteger().mod(domainParams.getN()).equals(r)) {
                    System.err.println("❌ Échec de la vérification de signature ECDSA pour " + cert.getSubjectX500Principal());
                    return false;
                }

                System.out.println("✔ Vérification de signature ECDSA réussie pour " + cert.getSubjectX500Principal());
            }

            return true;
        } catch (Exception e) {
            System.err.println("❌ Erreur lors de la vérification de signature ECDSA : " + e.getMessage());
            return false;
        }
    }
}
