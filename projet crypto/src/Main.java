import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) {

        //Vérification des arguments de la commande (le nombre d'argument et si l'orthographe de la commande est le bon)
        if (args.length != 4 || !args[0].equals("validate-cert") || !args[1].equals("-format")) {
            System.err.println("Erreur: Mauvais format d'arguments.");
            System.err.println("Usage attendu: validate-cert -format DER|PEM <chemin_du_certificat>");
            return;
        }


        String format = args[2];
        String filePath = args[3];

        X509Certificate cert = null;

        //Lancement des fonctions selon les arguments
        try {
            if (format.equalsIgnoreCase("DER")) {
                //Si dans les Arguments le format est DER
                cert = ValidateCert.affichage_DER(filePath);
            } else if (format.equalsIgnoreCase("PEM")) {
                //Si dans les Arguments le format est PEM
                cert = ValidateCert.affichage_PEM(filePath);
            } else {
                //Si dans les Arguments le format est invalide
                System.err.println("Erreur: Format non reconnu. Utilisez DER ou PEM.");
                return;
            }

            //Afficher le certificat
            ValidateCert.afficherInfosCertificat(cert);

            //Vérification de la signature
            System.out.println("=== Vérification de la signature ===");
            if (ValidateCert.verifierSignature(cert)) {
                System.out.println("La signature du certificat est valide.");
            } else {
                System.out.println("La signature du certificat est invalide.");
            }

            //Vérification de la validité
            System.out.println("=== Vérification de la validité ===");
            if (ValidateCert.verifierDate(cert)) {
                System.out.println("Le certificat est valide en termes de date.");
            } else {
                System.out.println("Le certificat est expiré ou non valide.");
            }

            //Vérification de l'usage des clés
            System.out.println("=== Vérification de l'usage des clés ===");
            ValidateCert.verifierKeyUsage(cert);

            //Vérification de l'algorithme et de la signature
            System.out.println("=== Vérification de l'algorithme et de la signature ===");
            ValidateCert.verifierAlgorithmeEtSignature(cert);

        } catch (Exception e) {
            System.err.println("Erreur lors de l'analyse du certificat: " + e.getMessage());
        }
    }
}