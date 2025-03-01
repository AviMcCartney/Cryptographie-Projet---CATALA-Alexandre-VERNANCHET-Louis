//Importation des classes nécessaires
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class ValidateCert {
    //Fonction qui charge un certificat X.509 au format DER depuis un fichier donné
    //qui renvoie un objet X509Certificate
    //et renvoie une exception s'il y a une erreur dans la lecture du fichier
    public static X509Certificate affichage_DER(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(filePath)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    //Fonction qui charge un certificat X.509 au format PEM depuis un fichier donné
    //qui renvoie un objet X509Certificate
    //et renvoie une exception s'il y a une erreur dans la lecture du fichier
    public static X509Certificate affichage_PEM(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        //Lecture du fichier en tant que chaine de caractères
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)));
        //extraction de la base64 en supprimant les en-têtes et les espaces 
        String base64Cert = pemContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(base64Cert);
        //Conversion des données décodées en un certificat x509
        try (InputStream inStream = new ByteArrayInputStream(decoded)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    //Fonction permettant de vérifier la signature d'un certificat en utilisant sa propre clé publique
    //grâce à la méthode verify. Cette fonction renvoie true si la signature est valide,
    //false avec un message d'erreur sinon.
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

    //Fonction qui affiche les usages de clé qui sont définis dans un certificat x509, grâce à l'extension
    //keyUsage du certificat et la méthode getKeyUsage
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

    //Fonction qui permet la vérification de la date d'expiration du certificat.
    //La méthode checkValidity prend la date de début et de fin de validité et les compare à la date actuelle.
    //Puis on renvoie true si le certificat est valide, false avec un message d'erreur sinon
    public static boolean verifierDate(X509Certificate cert){
        try{
            cert.checkValidity();
            return true;
        } catch (Exception e){
            System.err.println("Échec de la verification de la date" + e.getMessage());
            return false;
        }
    }

    //Fonction qui verifie l'algorithme de signature ainsi que la validité de la signature.
    public static void verifierAlgorithmeEtSignature(X509Certificate cert) {
        try {
            //récupération de l'algorithme de signature utilisé
            String algo = cert.getSigAlgName();
            //récupération de la signature
            byte[] signature = cert.getSignature();
            //Récupération de la clé publique
            PublicKey publicKey = cert.getPublicKey();
            //Création d'un objet Signature à partir de l'algorithme de signature
            Signature sig = Signature.getInstance(algo);
            //Initialisation de l'objet
            sig.initVerify(publicKey);
            //Mise à jour de l'objet avce la structure du certificat
            sig.update(cert.getTBSCertificate());
            //verification de la signature en comparant les données signées avec la signature extraite
            boolean verified = sig.verify(signature);
            //Affichage des résultats
            System.out.println("Algorithme de signature: " + algo);
            System.out.println("Signature vérifiée: " + (verified ? "✔ Valide" : "❌ Invalide"));
        } catch (Exception e) {
            System.err.println("Échec de la vérification de l'algorithme et de la signature: " + e.getMessage());
        }
    }

}
