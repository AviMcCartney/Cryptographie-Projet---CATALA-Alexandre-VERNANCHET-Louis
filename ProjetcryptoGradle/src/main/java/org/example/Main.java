package org.example;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        //Vérification de la saisie utilisateur
        if (args.length < 4) {
            afficherAide();
            return;
        }
        //Enregistrement de ce qui est saisi dans des variables
        String commande = args[0];
        String format = args[2];

        try {
            //Si on a un seul certificat
            if (commande.equals("validate-cert")) {
                //On vérifie le nombre de paramètres
                if (args.length != 4) {
                    afficherAide();
                    return;
                }

                //Lecture du fichier selon le format
                String filePath = args[3];
                X509Certificate cert = chargerCertificat(format, filePath);

                //Vérification de la lecture
                if (cert == null) {
                    System.err.println("Échec du chargement du certificat.");
                    return;
                }

                //Afficher les informations du certificat
                afficherInfos(cert);

                //Vérification de la signature en fonction de l'algorithme
                verifierSignature(List.of(cert));

                //Vérifications des propriétés du certificat
                verifierProprietesCertificat(List.of(cert));

            } // Si on a une chaîne de certificat
            else if (commande.equals("validate-cert-chain")) {
                //On vérifie le nombre de paramètres
                if (args.length < 5) {
                    afficherAide();
                    return;
                }

                //Lecture des fichiers selon le format
                List<X509Certificate> certChain = chargerChaineCertificats(format, args);

                //Vérification de la lecture
                if (certChain.isEmpty()) {
                    System.err.println("Erreur : Impossible de charger la chaîne de certificats.");
                    return;
                }

                //Afficher les informations des certificats
                afficherInfosCertificatChaine(certChain);

                //Validation de la chaîne
                System.out.println("\n=== Validation de la chaîne de certificats ===");
                if (ValidateCert.verifierChaineCertificats(certChain)) {
                    System.out.println("La chaîne de certificats est valide !");
                } else {
                    System.err.println("La chaîne de certificats est invalide.");
                }

                // Vérification de la signature
                verifierSignature(certChain);

                // Vérification des propriétés des certificats
                verifierProprietesCertificat(certChain);

            } else {
                //Affichage du bon format de commande à saisir
                afficherAide();
            }
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }

    /**
     * Charge un certificat X.509 à partir d'un fichier en format DER ou PEM
     * @param format Format du certificat ("DER" ou "PEM")
     * @param filePath Chemin du fichier du certificat
     * @return Le certificat X509 chargé, ou null en cas d'erreur
     */
    private static X509Certificate chargerCertificat(String format, String filePath) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                System.err.println("Fichier introuvable : " + filePath);
                return null;
            }

            if (format.equalsIgnoreCase("DER")) {
                return ValidateCert.affichage_DER(filePath);
            } else if (format.equalsIgnoreCase("PEM")) {
                return ValidateCert.affichage_PEM(filePath);
            } else {
                System.err.println("Format non reconnu. Utilisez DER ou PEM.");
                return null;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du chargement du certificat : " + e.getMessage());
            return null;
        }
    }

    /**
     * Charge une chaîne de certificats X.509 à partir des fichiers spécifiés
     * @param format Format des certificats ("DER" ou "PEM")
     * @param args Tableau contenant les chemins des fichiers des certificats
     * @return Une liste de certificats X.509 chargés, ou une liste vide en cas d'erreur
     */
    private static List<X509Certificate> chargerChaineCertificats(String format, String[] args) {
        List<X509Certificate> certChain = new ArrayList<>();
        for (int i = 3; i < args.length; i++) {
            X509Certificate cert = chargerCertificat(format, args[i]);
            if (cert != null) {
                certChain.add(cert);
            } else {
                System.err.println("Erreur lors du chargement du certificat : " + args[i]);
            }
        }
        return certChain;
    }

    /**
     * Affiche les informations détaillées d'un certificat unique
     * @param cert Certificat X.509 dont on veut afficher les informations
     */
    private static void afficherInfos(X509Certificate cert) {
        System.out.println("\n=== Informations du Certificat ===");
        ValidateCert.afficherInfosCertificat(cert);

        System.out.println("\n=== Vérification de la validité ===");
        if (ValidateCert.verifierDate(cert)) {
            System.out.println("Le certificat est valide en termes de date.");
        } else {
            System.out.println("Le certificat est expiré ou non valide.");
        }
    }

    /**
     * Affiche les informations de tous les certificats d'une chaîne de certification
     * @param certChain Liste des certificats X.509
     */
    private static void afficherInfosCertificatChaine(List<X509Certificate> certChain) {
        System.out.println("\n=== Informations de la Chaîne de Certificats ===");

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);
            String niveauCertificat;

            if (i == 0) {
                niveauCertificat = "Root CA";
            } else if (i == certChain.size() - 1) {
                niveauCertificat = "Leaf";
            } else {
                niveauCertificat = "Intermédiaire";
            }

            System.out.println("\n" + niveauCertificat + " : " + cert.getSubjectX500Principal());
            ValidateCert.afficherInfosCertificat(cert);
        }
    }

    /**
     * Vérifie la signature des certificats en fonction de leur algorithme (RSA ou ECDSA)
     * @param certs Liste des certificats dont la signature doit être vérifiée
     */
    private static void verifierSignature(List<X509Certificate> certs) {
        String sigAlg = certs.getFirst().getSigAlgName().toUpperCase();

        if (sigAlg.contains("RSA")) {
            System.out.println("\n=== Vérification de la signature RSA ===");
            if (ValidateCert.verifierSignatureRSA_BigInteger(certs)) {
                System.out.println("La signature RSA est valide.");
            } else {
                System.err.println("La signature RSA est invalide.");
            }
        } else if (sigAlg.contains("ECDSA")) {
            System.out.println("\n=== Vérification de la signature ECDSA ===");
            if (ValidateCert.verifierSignatureECDSA(certs)) {
                System.out.println("La signature ECDSA est valide.");
            } else {
                System.err.println("La signature ECDSA est invalide.");
            }
        } else {
            System.err.println("Algorithme de signature non supporté : " + sigAlg);
        }
    }

    /**
     * Vérifie les propriétés du certificat ou de la chaîne de certificats (KeyUsage, BasicConstraints)
     * @param certs Liste des certificats à vérifier
     */
    private static void verifierProprietesCertificat(List<X509Certificate> certs) {
        System.out.println("\n=== Vérification des KeyUsage ===");
        if (ValidateCert.verifierKeyUsage(certs)) {
            System.out.println("Tous les certificats ont des KeyUsage valides !");
        } else {
            System.err.println("Erreur : Un ou plusieurs certificats ont un KeyUsage invalide.");
        }

        System.out.println("\n=== Vérification des Basic Constraints ===");
        if (ValidateCert.verifierBasicConstraints(certs)) {
            System.out.println("Tous les certificats respectent les Basic Constraints !");
        } else {
            System.err.println("Erreur : Un ou plusieurs certificats ont des Basic Constraints invalides.");
        }
    }

    // Méthode pour afficher l'aide sur la ligne de commande
    private static void afficherAide() {
        System.out.println("\nUsage : ");
        System.out.println(" - validate-cert -format DER|PEM <fichier_certificat>");
        System.out.println(" - validate-cert-chain -format DER|PEM <certificatRoot> <certificat2> ... <certificatN>");
    }
}
