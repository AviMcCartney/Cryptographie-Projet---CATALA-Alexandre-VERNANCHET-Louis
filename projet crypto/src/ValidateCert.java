/**
 * Importation des classes nécessaires
 */
import java.io.*;
import java.nio.file.*;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

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

    public static void afficherInfosCertificat(X509Certificate cert) {
        System.out.println("=== Informations du Certificat ===");
        System.out.println("Sujet : " + cert.getSubjectX500Principal());
        System.out.println("Émetteur : " + cert.getIssuerX500Principal());
        System.out.println("Date de début de validité : " + cert.getNotBefore());
        System.out.println("Date de fin de validité : " + cert.getNotAfter());
        System.out.println("Numéro de série : " + cert.getSerialNumber());
    }

    public static void main(String[] args) {
        if (args.length != 4 || !args[0].equals("validate-cert") || !args[1].equals("-format")) {
            System.err.println("Erreur: Mauvais format d'arguments.");
            System.err.println("Usage attendu: validate-cert -format DER|PEM <chemin_du_certificat>");
            return;
        }

        String format = args[2];
        String filePath = args[3];

        X509Certificate cert = null;

        try {
            if (format.equalsIgnoreCase("DER")) {
                cert = affichage_DER(filePath);
            } else if (format.equalsIgnoreCase("PEM")) {
                cert = affichage_PEM(filePath);
            } else {
                System.err.println("Erreur: Format non reconnu. Utilisez DER ou PEM.");
                return;
            }

            afficherInfosCertificat(cert);

            System.out.println("=== Vérification de la signature ===");
            if (verifierSignature(cert)) {
                System.out.println("La signature du certificat est valide.");
            } else {
                System.out.println("La signature du certificat est invalide.");
            }

            System.out.println("=== Vérification de la validité ===");
            if (verifierDate(cert)) {
                System.out.println("Le certificat est valide en termes de date.");
            } else {
                System.out.println("Le certificat est expiré ou non valide.");
            }

            System.out.println("=== Vérification de l'usage des clés ===");
            verifierKeyUsage(cert);

            System.out.println("=== Vérification de l'algorithme et de la signature ===");
            verifierAlgorithmeEtSignature(cert);

        } catch (Exception e) {
            System.err.println("Erreur lors de l'analyse du certificat: " + e.getMessage());
        }
    }
}
