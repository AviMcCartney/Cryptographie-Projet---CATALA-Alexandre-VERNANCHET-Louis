package org.example.Certificats.Validation;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.example.Certificats.Utiles.CRLManager.telechargerCRL;
import static org.example.Certificats.Utiles.OCSPManager.*;

public class ValidationCertificat {
    /**
     * Vérifie la signature des certificats en fonction de leur algorithme (RSA ou ECDSA)
     * @param certs Liste des certificats dont la signature doit être vérifiée
     */
    public static void verifierSignature(List<X509Certificate> certs) {
        String sigAlg = certs.getFirst().getSigAlgName().toUpperCase();

        if (sigAlg.contains("RSA")) {
            System.out.println("\n=== Vérification de la signature RSA ===");
            if (VerifierSignature.verifierSignatureRSA_BigInteger(certs)) {
                System.out.println("La signature RSA est valide.");
            } else {
                System.err.println("La signature RSA est invalide.");
            }
        } else if (sigAlg.contains("ECDSA")) {
            System.out.println("\n=== Vérification de la signature ECDSA ===");
            if (VerifierSignature.verifierSignatureECDSA(certs)) {
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
    public static void verifierProprietesCertificat(List<X509Certificate> certs) {
        System.out.println("\n=== Vérification des KeyUsage ===");
        if (VerifierExtension.verifierKeyUsage(certs)) {
            System.out.println("Tous les certificats ont des KeyUsage valides !");
        } else {
            System.err.println("Erreur : Un ou plusieurs certificats ont un KeyUsage invalide.");
        }

        System.out.println("\n=== Vérification des Basic Constraints ===");
        if (VerifierExtension.verifierBasicConstraints(certs)) {
            System.out.println("Tous les certificats respectent les Basic Constraints !");
        } else {
            System.err.println("Erreur : Un ou plusieurs certificats ont des Basic Constraints invalides.");
        }
    }
    /**
     * Vérifie si un certificat est révoqué via OCSP
     * @param cert Le certificat à vérifier
     * @param issuerCert Le certificat de l'autorité de certification émettrice
     * @return true si le certificat est révoqué, false sinon
     */
    private static boolean verifierRevocationOCSP(X509Certificate cert, X509Certificate issuerCert) {
        try {
            //Récupérer l'URL OCSP depuis le certificat
            Optional<String> ocspUrlOpt = extraireOCSPUrl(cert);
            if (ocspUrlOpt.isEmpty()) {
                System.err.println("Aucune URL OCSP trouvée pour " + cert.getSubjectX500Principal());
                return false;
            }
            String ocspUrl = ocspUrlOpt.get();

            //Construire et envoyer la requête OCSP
            return Optional.ofNullable(creerRequeteOCSP(cert, issuerCert))
                    .map(req -> envoyerRequeteOCSP(ocspUrl, req))
                    .orElse(false);

        } catch (Exception e) {
            System.err.println("Erreur OCSP : " + e.getMessage());
            return false;
        }
    }

    public static void verifierRevocation(List<X509Certificate> certChain) {
        System.out.println("\n=== Vérification de la révocation via OCSP et CRL ===");

        Collections.reverse(certChain); // Vérifier du Leaf vers le Root

        for (int i = certChain.size() - 1; i > 0; i--) {
            X509Certificate certToCheck = certChain.get(i);
            X509Certificate issuerCert = certChain.get(i - 1);

            // Vérification via OCSP si possible
            boolean estRevoqueOCSP = verifierRevocationOCSP(certToCheck, issuerCert);
            if (estRevoqueOCSP) {
                System.err.println("Le certificat " + certToCheck.getSubjectX500Principal() + " est révoqué selon OCSP !");
                return;
            }

            // Si OCSP n'est pas disponible, bascule sur CRL
            boolean estRevoqueCRL = verifierRevocationAvecCRL(certToCheck, List.of(issuerCert));
            if (estRevoqueCRL) {
                System.err.println("Le certificat " + certToCheck.getSubjectX500Principal() + " est révoqué selon la CRL !");
                return;
            }

            System.out.println("Le certificat " + certToCheck.getSubjectX500Principal() + " n'est pas révoqué.");
        }
    }

    /**
     * Vérifie si un certificat est révoqué en téléchargeant et en validant sa CRL
     * @param cert Certificat à vérifier
     * @param possibleIssuers Liste des certificats émetteurs possibles
     * @return true si le certificat est révoqué, false sinon
     */
    private static boolean verifierRevocationAvecCRL(X509Certificate cert, List<X509Certificate> possibleIssuers) {
        try {
            // Vérifier si c'est un Root CA
            if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                System.out.println("Le certificat " + cert.getSubjectX500Principal() + " est un Root CA. Vérification CRL ignorée.");
                return false;
            }

            X509CRL crl = telechargerCRL(cert);
            if (crl == null) {
                System.err.println("Impossible de récupérer la CRL pour la vérification.");
                return false;
            }

            X509Certificate crlIssuerCert = null;
            for (X509Certificate issuer : possibleIssuers) {
                if (crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                    crlIssuerCert = issuer;
                    break;
                }
            }

            if (crlIssuerCert == null) {
                System.err.println("Aucun certificat trouvé correspondant à l’émetteur de la CRL");
                return false;
            }

            // Vérification de la signature de la CRL
            try {
                crl.verify(crlIssuerCert.getPublicKey());
            } catch (Exception e) {
                System.err.println("Erreur de vérification de la signature de la CRL : " + e.getMessage());
                return false;
            }

            // Vérification de la révocation du certificat
            X509CRLEntry crlEntry = crl.getRevokedCertificate(cert.getSerialNumber());
            return crlEntry != null;

        } catch (Exception e) {
            System.err.println("Erreur lors de la vérification de révocation : " + e.getMessage());
            return false;
        }
    }

}
