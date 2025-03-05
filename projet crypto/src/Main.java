import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        if (args.length < 4) {
            afficherAide();
            return;
        }

        String commande = args[0];
        String format = args[2];

        try {
            if (commande.equals("validate-cert")) {
                if (args.length != 4) {
                    afficherAide();
                    return;
                }

                String filePath = args[3];
                X509Certificate cert = chargerCertificat(format, filePath);

                if (cert == null) {
                    System.err.println("❌ Échec du chargement du certificat.");
                    return;
                }

                afficherInfos(cert);

            } else if (commande.equals("validate-cert-chain")) {
                if (args.length < 5) {
                    afficherAide();
                    return;
                }

                List<X509Certificate> certChain = new ArrayList<>();

                // Charger les certificats en respectant l'ordre Root → Intermediate → Leaf
                for (int i = 3; i < args.length; i++) {
                    X509Certificate cert = chargerCertificat(format, args[i]);

                    if (cert != null) {
                        certChain.add(cert);
                    } else {
                        System.err.println("❌ Erreur lors du chargement du certificat : " + args[i]);
                    }
                }

                System.out.println("\n=== Validation de la chaîne de certificats ===");
                if (ValidateCert.verifierChaineCertificats(certChain)) {
                    System.out.println("✔ La chaîne de certificats est valide !");
                } else {
                    System.err.println("❌ La chaîne de certificats est invalide.");
                }
            } else {
                afficherAide();
            }
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }

    private static X509Certificate chargerCertificat(String format, String filePath) {
        try {
            // Vérifie si le fichier existe avant de le lire
            File file = new File(filePath);
            if (!file.exists()) {
                System.err.println("❌ Fichier introuvable : " + filePath);
                return null;
            }

            if (format.equalsIgnoreCase("DER")) {
                return ValidateCert.affichage_DER(filePath);
            } else if (format.equalsIgnoreCase("PEM")) {
                return ValidateCert.affichage_PEM(filePath);
            } else {
                System.err.println("Erreur : Format non reconnu. Utilisez DER ou PEM.");
                return null;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du chargement du certificat : " + e.getMessage());
            return null;
        }
    }

    private static void afficherInfos(X509Certificate cert) {
        System.out.println("\n=== Informations du Certificat ===");
        ValidateCert.afficherInfosCertificat(cert);

        System.out.println("\n=== Vérification de la signature ===");
        if (ValidateCert.verifierSignature(cert)) {
            System.out.println("✔ La signature du certificat est valide.");
        } else {
            System.out.println("❌ La signature du certificat est invalide.");
        }

        System.out.println("\n=== Vérification de la validité ===");
        if (ValidateCert.verifierDate(cert)) {
            System.out.println("✔ Le certificat est valide en termes de date.");
        } else {
            System.out.println("❌ Le certificat est expiré ou non valide.");
        }

        System.out.println("\n=== Vérification de l'usage des clés ===");
        ValidateCert.verifierKeyUsage(cert);

        System.out.println("\n=== Vérification de l'algorithme et de la signature ===");
        ValidateCert.verifierAlgorithmeEtSignature(cert);
    }

    private static void afficherAide() {
        System.out.println("\nUsage : ");
        System.out.println(" - validate-cert -format DER|PEM <fichier_certificat>");
        System.out.println(" - validate-cert-chain -format DER|PEM <certificat1> <certificat2> ... <certificatN>");
    }
}
