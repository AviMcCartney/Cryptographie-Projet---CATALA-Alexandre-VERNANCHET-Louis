package org.example.Certificats.Utiles;

import java.security.cert.X509Certificate;
import java.util.List;

public class utilitaire {
    /**
     * Vérifie si une liste de certificats est vide ou nulle
     * @param chain Liste de certificats
     * @return true si la liste est vide ou nulle, false sinon
     */
    public static boolean IsChainNull (List<X509Certificate> chain){
        if (chain == null || chain.isEmpty()) {
            System.err.println("Erreur : Liste de certificats vide ou nulle.");
            return true;
        }
        return false;
    }
}
