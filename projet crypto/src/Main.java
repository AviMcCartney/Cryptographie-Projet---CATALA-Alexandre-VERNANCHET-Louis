//Import des class
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        //Chemins absolus des certificats
        String derFilePath = "C:\\Users\\louis\\OneDrive\\Documents\\GitHub\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\tbscertificate\\DER\\tbs_root_der.der";
        String pemFilePath  = "C:\\Users\\louis\\OneDrive\\Documents\\GitHub\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\tbscertificate\\PEM\\tbs_root_pem.crt";

        try {
            //Appelle des fonctions avec le fichier DER
            System.out.println("Test du certificat DER :");
            X509Certificate derCert = ValidateCert.affichage_DER(derFilePath);
            afficherDetails(derCert);
            verifierEtAfficherSignature(derCert);
            verifierEtAfficherKeyUsage(derCert);
            verifierDate(derCert);
            verifierAlgorithmeEtSignature(derCert);

            //Appelle des fonctions avec le fichier PEM
            System.out.println("\nTest du certificat PEM :");
            X509Certificate pemCert = ValidateCert.affichage_PEM(pemFilePath);
            afficherDetails(pemCert);
            verifierEtAfficherSignature(pemCert);
            verifierEtAfficherKeyUsage(pemCert);
            verifierDate(pemCert);
            verifierAlgorithmeEtSignature(pemCert);

        } catch (Exception e) {
            //Gestion d'erreur
            System.err.println("Erreur : " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void afficherDetails(X509Certificate cert) {
        if (cert != null) {
            System.out.println("--------------------------------");
            System.out.println("Sujet : " + cert.getSubjectX500Principal());
            System.out.println("Émetteur : " + cert.getIssuerX500Principal());
            System.out.println("Valide du : " + cert.getNotBefore());
            System.out.println("Valide jusqu'à : " + cert.getNotAfter());
            System.out.println("Numéro de série : " + cert.getSerialNumber());
            System.out.println("Algorithme de signature : " + cert.getSigAlgName());
            System.out.println("Clé publique : " + cert.getPublicKey());
            System.out.println("--------------------------------");
        } else {
            System.out.println("Le certificat est null.");
        }
    }

    private static void verifierEtAfficherSignature(X509Certificate cert) {
        if (ValidateCert.verifierSignature(cert)) {
            System.out.println("✅ Signature valide.");
        } else {
            System.out.println("❌ Signature invalide.");
        }
    }

    private static void verifierEtAfficherKeyUsage(X509Certificate cert) {
        System.out.println("\nVérification de l'extension KeyUsage :");
        ValidateCert.verifierKeyUsage(cert);
    }

    private static void verifierDate(X509Certificate cert){
        if(ValidateCert.verifierDate(cert)){
            System.out.println("\n✅ Date valide.");
        } else {
            System.out.println("\n❌ Date invalide.");
        }
    }

    private static void verifierAlgorithmeEtSignature(X509Certificate cert) {
        System.out.println("\nVérification de l'algorithme de signature et de la signature :");
        ValidateCert.verifierAlgorithmeEtSignature(cert);
    }
}
