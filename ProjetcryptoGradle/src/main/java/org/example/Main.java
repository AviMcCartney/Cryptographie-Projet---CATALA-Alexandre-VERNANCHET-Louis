package org.example;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.example.Certificats.Affichage.ManageAffichage.*;
import static org.example.Certificats.Chargement.ChargeCertificats.*;
import static org.example.Certificats.Validation.ValidationCertificat.*;
import static org.example.Certificats.Validation.VerifierSignature.verifierChaineCertificats;

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
                if (verifierChaineCertificats(certChain)) {
                    System.out.println("La chaîne de certificats est valide !");
                } else {
                    System.err.println("La chaîne de certificats est invalide.");
                }

                //Vérification de la signature
                verifierSignature(certChain);

                //Vérification des propriétés des certificats
                verifierProprietesCertificat(certChain);

                //Vérification de la CRL
                verifierRevocation(certChain);

            } else {
                //Affichage du bon format de commande à saisir
                afficherAide();
            }
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
    }
}
