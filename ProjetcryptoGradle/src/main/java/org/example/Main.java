package org.example;

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
                    System.err.println("Échec du chargement du certificat.");
                    return;
                }

                afficherInfos(cert);

                // Vérification de la signature en fonction de l'algorithme
                verifierSignature(List.of(cert));

                // Vérifications des propriétés du certificat
                verifierProprietesCertificat(List.of(cert));

            } else if (commande.equals("validate-cert-chain")) {
                if (args.length < 5) {
                    afficherAide();
                    return;
                }

                List<X509Certificate> certChain = chargerChaineCertificats(format, args);

                if (certChain.isEmpty()) {
                    System.err.println("Erreur : Impossible de charger la chaîne de certificats.");
                    return;
                }

                afficherInfosCertificatChaine(certChain);

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
                afficherAide();
            }
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }

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
                niveauCertificat = "Intermediaire";
            }

            System.out.println("\n" + niveauCertificat + " : " + cert.getSubjectX500Principal());
            ValidateCert.afficherInfosCertificat(cert);
        }
    }

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

    private static void afficherAide() {
        System.out.println("\nUsage : ");
        System.out.println(" - validate-cert -format DER|PEM <fichier_certificat>");
        System.out.println(" - validate-cert-chain -format DER|PEM <certificatRoot> <certificat2> ... <certificatN>");
    }
}
