package org.example.Certificats.Affichage;

import org.example.Certificats.Validation.VerifierExtension;

import java.security.cert.X509Certificate;
import java.util.List;

public class ManageAffichage {
    /**
     * Affiche les informations générales d'un certificat X.509
     * @param cert Certificat X.509 dont on veut afficher les informations
     */
    private static void afficherInfosCertificat(X509Certificate cert) {
        System.out.println("=== Informations du Certificat ===");
        System.out.println("Sujet : " + cert.getSubjectX500Principal());
        System.out.println("Émetteur : " + cert.getIssuerX500Principal());
        System.out.println("Date de début de validité : " + cert.getNotBefore());
        System.out.println("Date de fin de validité : " + cert.getNotAfter());
        System.out.println("Numéro de série : " + cert.getSerialNumber());
    }

    /**
     * Affiche les informations détaillées d'un certificat unique
     * @param cert Certificat X.509 dont on veut afficher les informations
     */
    public static void afficherInfos(X509Certificate cert) {
        System.out.println("\n=== Informations du Certificat ===");
        afficherInfosCertificat(cert);

        System.out.println("\n=== Vérification de la validité ===");
        if (VerifierExtension.verifierDate(cert)) {
            System.out.println("Le certificat est valide en termes de date.");
        } else {
            System.out.println("Le certificat est expiré ou non valide.");
        }
    }

    /**
     * Affiche les informations de tous les certificats d'une chaîne de certification
     * @param certChain Liste des certificats X.509
     */
    public static void afficherInfosCertificatChaine(List<X509Certificate> certChain) {
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
            afficherInfosCertificat(cert);
        }
    }

    // Méthode pour afficher l'aide sur la ligne de commande
    public static void afficherAide() {
        System.out.println("\nUsage : ");
        System.out.println(" - validate-cert -format DER|PEM <fichier_certificat>");
        System.out.println(" - validate-cert-chain -format DER|PEM <certificatRoot> <certificat2> ... <certificatN>");
    }
}
