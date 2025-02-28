import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        String derFilePath = "C:\\Users\\Alexandre\\OneDrive\\Bureau\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\Lemonde\\DER\\GlobalSign_root_lemonde_der.der";
        String pemFilePath  = "C:\\Users\\Alexandre\\OneDrive\\Bureau\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\Lemonde\\PEM\\GlobalSign_root_lemonde_pem.crt";

        try {
            System.out.println("Test du certificat DER :");
            X509Certificate derCert = ValidateCert.affichage_DER(derFilePath);
            afficherDetails(derCert);
            verifierEtAfficherSignature(derCert);
            verifierEtAfficherKeyUsage(derCert);

            System.out.println("\nTest du certificat PEM :");
            X509Certificate pemCert = ValidateCert.affichage_PEM(pemFilePath);
            afficherDetails(pemCert);
            verifierEtAfficherSignature(pemCert);
            verifierEtAfficherKeyUsage(pemCert);

        } catch (Exception e) {
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
}

