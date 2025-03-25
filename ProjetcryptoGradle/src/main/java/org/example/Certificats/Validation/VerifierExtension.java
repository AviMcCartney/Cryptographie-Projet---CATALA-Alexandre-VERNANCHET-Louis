package org.example.Certificats.Validation;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.example.Certificats.Utiles.utilitaire.IsChainNull;

public class VerifierExtension {
    /**
     * Vérifie les usages de clé (KeyUsage) d'une chaîne de certificats
     * @param certChain Liste des certificats à vérifier
     * @return true si tous les certificats respectent les usages clés attendus, false sinon
     */
    public static boolean verifierKeyUsage(List<X509Certificate> certChain) {
        if (IsChainNull(certChain)) {
            return false;
        }

        //Si on a un seul certificat, c'est un root
        boolean isSingleRoot = (certChain.size() == 1);

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);
            boolean[] keyUsage = cert.getKeyUsage();

            //Si l'extension KeyUsage n'est pas définie, on considère qu'il n'y a pas de restriction
            if (keyUsage == null) {
                System.out.println("Aucun KeyUsage spécifié, le certificat est peut-être valide.");
                continue;
            }

            boolean hasRequiredUsage = false;
            for (int j = 0; j < keyUsage.length; j++) {
                if (keyUsage[j]) {
                    //Vérification selon le type de certificat
                    if (!isSingleRoot && i == 0 && j == 0) hasRequiredUsage = true; // Leaf → Digital Signature
                    if ((isSingleRoot || i > 0) && j == 5) hasRequiredUsage = true; // Root ou intermédiaire → Certificate Signing
                }
            }

            //Vérification finale en fonction du type de certificat
            if (!isSingleRoot && i == 0 && !hasRequiredUsage) {
                System.err.println("Le certificat Leaf doit avoir 'Digital Signature'.");
                return false;
            }
            if ((isSingleRoot || i > 0) && !hasRequiredUsage) {
                System.err.println("Le certificat Intermédiaire/Root doit avoir 'Certificate Signing'.");
                return false;
            }
        }
        return true;
    }

    /**
     * Vérifie si un certificat est toujours valide en termes de date
     * @param cert Certificat à vérifier
     * {@link X509Certificate#checkValidity() prend la date de début et de fin de validité et les compare à la date actuelle}
     * @return true si la date est valide, false sinon
     */
    public static boolean verifierDate(X509Certificate cert){
        try{
            cert.checkValidity();
            return true;
        } catch (Exception e) {
            System.err.println("Échec de la vérification de la date: " + e.getMessage());
            return false;
        }
    }

    /**
     * Vérifie la validité des Basic Constraints pour une chaîne de certificats
     * @param certChain Liste des certificats à vérifier
     * {@link X509Certificate#getBasicConstraints() Récupération de l'extension BasicConstraint}
     * @return true si les Basic Constraints sont respectées, false sinon
     */
    public static boolean verifierBasicConstraints(List<X509Certificate> certChain) {

        if (IsChainNull(certChain)) {
            return false;
        }

        boolean isSingleRoot = (certChain.size() == 1);

        for (int i = 0; i < certChain.size(); i++) {
            X509Certificate cert = certChain.get(i);

            // Déterminer le rôle du certificat
            boolean isRoot = isSingleRoot || i == certChain.size() - 1;
            boolean isLeaf = !isSingleRoot && i == 0;
            boolean isLastInterm = (i == certChain.size() - 2);

            int basicConstraints = cert.getBasicConstraints();

            if (isLeaf) {
                // Vérification que le certificat Leaf n'est pas un CA
                if (basicConstraints != -1) {
                    System.err.println("Erreur : Le certificat Leaf ne doit pas être un CA.");
                    return false;
                }
            } else {
                // Vérification que le certificat est un CA
                if (basicConstraints == -1) {
                    System.err.println("Erreur : Le certificat " + cert.getSubjectX500Principal() +
                            " n'est pas un CA, mais il est dans la chaîne de certification.");
                    return false;
                }

                // Vérification du pathLenConstraint pour les intermédiaires
                int expectedMaxIntermediates = certChain.size() - (i + 1);

                if (!isRoot && !isLastInterm && basicConstraints >= 0 && basicConstraints < expectedMaxIntermediates) {
                    System.err.println("Erreur : Le certificat " + cert.getSubjectX500Principal() +
                            " a un pathLenConstraint trop faible (" + basicConstraints + "), il ne peut pas signer autant d'intermédiaires.");
                    return false;
                }
            }
        }
        return true;
    }

}
