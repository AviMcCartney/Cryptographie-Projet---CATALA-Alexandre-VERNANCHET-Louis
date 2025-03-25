package org.example.Certificats.Utiles;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.*;

import java.io.*;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CRLManager {

    //Dossier pour stocker les CRL
    private static final String CRL_CACHE_DIR = "cache_crl";

    //HashMap pour stocker les fichier en cache
    private static final Map<String, X509CRL> crlCache = new HashMap<>();

    /**
     * Télécharge la CRL depuis l'URL extraite du certificat
     * Utilise un cache pour éviter les téléchargements inutiles :
     * Vérifie d'abord si la CRL est en mémoire,
     * Si elle n'est pas en mémoire, tente de la charger depuis le disque,
     * Si elle n'est ni en mémoire ni sur le disque, elle est téléchargée et mise en cache.
     * @param cert Le certificat X.509 dont on veut vérifier la révocation
     * @return L'objet X509CRL correspondant, ou null en cas d'échec
     */
    public static X509CRL telechargerCRL(X509Certificate cert) {
        try {
            String crlUrl = extraireCRLDistributionPoint(cert);
            if (crlUrl == null) {
                System.err.println("Aucune URL CRL trouvée pour le certificat : " + cert.getSubjectX500Principal());
                return null;
            }

            //Vérifier d'abord si une CRL valide est en mémoire
            if (crlCache.containsKey(crlUrl)) {
                X509CRL cachedCRL = crlCache.get(crlUrl);
                if (cachedCRL.getNextUpdate().after(new Date())) {
                    System.out.println("Utilisation de la CRL en mémoire pour : " + crlUrl);
                    return cachedCRL;
                }
            }

            //Si non trouvée en mémoire, essayer de charger depuis le disque
            X509CRL crlFromDisk = chargerCRLDepuisDisque(crlUrl);
            if (crlFromDisk != null) {
                crlCache.put(crlUrl, crlFromDisk);
                return crlFromDisk;
            }

            //Si la CRL n'est pas en cache, la télécharger
            System.out.println("Téléchargement de la CRL depuis : " + crlUrl);
            try (InputStream crlStream = new URI(crlUrl).toURL().openStream()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL crl = (X509CRL) cf.generateCRL(crlStream);

                // Sauvegarde en mémoire et sur disque
                crlCache.put(crlUrl, crl);
                sauvegarderCRLSurDisque(crlUrl, crl);

                System.out.println("CRL téléchargée et mise en cache : " + crlUrl);
                return crl;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du téléchargement de la CRL : " + e.getMessage());
            return null;
        }
    }

    /**
     * Extrait l'URL de la CRL depuis le certificat
     * @param cert Certificat contenant l'extension CRL Distribution Points
     * @return L'URL de la CRL ou null en cas d'échec
     */
    private static String extraireCRLDistributionPoint(X509Certificate cert) {
        try {
            byte[] crlBytes = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crlBytes == null) {
                System.err.println("Aucune extension CRL trouvée");
                return null;
            }

            // Décodage ASN.1
            try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(crlBytes))) {
                ASN1OctetString octetString = ASN1OctetString.getInstance(asn1InputStream.readObject());
                try (ASN1InputStream asn1Stream2 = new ASN1InputStream(new ByteArrayInputStream(octetString.getOctets()))) {
                    CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Stream2.readObject());

                    for (DistributionPoint dp : crlDistPoint.getDistributionPoints()) {
                        DistributionPointName dpn = dp.getDistributionPoint();
                        if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                            for (GeneralName gn : GeneralNames.getInstance(dpn.getName()).getNames()) {
                                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                    return gn.getName().toString();
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de l'extraction de l'URL de la CRL : " + e.getMessage());
        }
        return null;
    }

    /**
     * Sauvegarde une CRL sur disque afin de pouvoir la réutiliser ultérieurement
     * La CRL est stockée dans un fichier sous un dossier dédié, avec un nom unique
     * @param crlUrl L'URL de la CRL à sauvegarder
     * @param crl L'objet X509CRL à enregistrer sur le disque
     */
    private static void sauvegarderCRLSurDisque(String crlUrl, X509CRL crl) {
        try {
            //Création du répertoire s'il n'existe pas
            File dir = new File(CRL_CACHE_DIR);
            if (!dir.exists() && !dir.mkdir()) {
                System.err.println("Erreur : Impossible de créer le dossier du cache CRL !");
                return;
            }

            //Création du fichier pour stocker la CRL (nom basé sur le hash de l'URL)
            File crlFile = new File(dir, crlUrl.hashCode() + ".crl"); // Nom unique pour la CRL
            try (FileOutputStream fos = new FileOutputStream(crlFile)) {
                fos.write(crl.getEncoded());
            }
            System.out.println("CRL sauvegardée sur disque : " + crlFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Erreur lors de la sauvegarde de la CRL : " + e.getMessage());
        }
    }

    /**
     * Charge une CRL depuis le disque si elle est disponible et encore valide
     * Si la CRL est expirée, elle est supprimée pour éviter une utilisation incorrecte
     * @param crlUrl L'URL de la CRL à charger
     * @return L'objet X509CRL chargé depuis le disque, ou null si indisponible ou expiré
     */
    private static X509CRL chargerCRLDepuisDisque(String crlUrl) {
        try {
            //Localisation du fichier de la CRL en cache
            File crlFile = new File(CRL_CACHE_DIR, crlUrl.hashCode() + ".crl");
            if (!crlFile.exists()) {
                return null; //Aucune CRL en cache
            }

            //Lecture de la CRL depuis le fichier
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (FileInputStream fis = new FileInputStream(crlFile)) {
                X509CRL crl = (X509CRL) cf.generateCRL(fis);
                //Vérification si la CRL est encore valide
                if (crl.getNextUpdate().after(new Date())) {
                    System.out.println("CRL chargée depuis le disque : " + crlFile.getAbsolutePath());
                    return crl;
                } else {
                    //Suppression de la CRL expirée
                    System.out.println("CRL expirée sur disque, suppression : " + crlFile.getAbsolutePath());
                    if (!crlFile.delete()) {
                        System.err.println("Erreur : Impossible de supprimer l'ancienne CRL expirée : " + crlFile.getAbsolutePath());
                    } else {
                        System.out.println("CRL expirée supprimée : " + crlFile.getAbsolutePath());
                    }

                    return null;
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du chargement de la CRL depuis le disque : " + e.getMessage());
            return null;
        }
    }
}
