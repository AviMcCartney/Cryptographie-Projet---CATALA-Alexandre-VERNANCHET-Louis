import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {
        String derFilePath = "C:\\Users\\louis\\OneDrive\\Documents\\GitHub\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\Lemonde\\DER\\GlobalSign_root_lemonde_der.der";
        String pemFilePath  = "C:\\Users\\louis\\OneDrive\\Documents\\GitHub\\Cryptographie-Projet---CATALA-Alexandre-VERNANCHET-Louis\\projet crypto\\Lemonde\\PEM\\badGlobalSign_root_lemonde_pem.crt";

        try {
            System.out.println("Test du certificat DER :");
            X509Certificate derCert = ValidateCert.affichage_DER(derFilePath);
            afficherDetails(derCert);
            verifierEtAfficherSignature(derCert);

            System.out.println("\nTest du certificat PEM :");
            X509Certificate pemCert = ValidateCert.affichage_PEM(pemFilePath);
            afficherDetails(pemCert);
            verifierEtAfficherSignature(pemCert);

        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void afficherDetails(X509Certificate cert) {
        if (cert != null) {
            System.out.println("--------------------------------");
            System.out.println("Sujet : " + cert.getSubjectDN());
            System.out.println("Émetteur : " + cert.getIssuerDN());
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
}

