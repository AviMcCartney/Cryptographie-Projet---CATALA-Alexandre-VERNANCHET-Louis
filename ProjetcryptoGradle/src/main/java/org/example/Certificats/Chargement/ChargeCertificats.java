package org.example.Certificats.Chargement;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ChargeCertificats {

    /**
     * Charge un certificat X.509 à partir d'un fichier en format DER ou PEM
     * @param format Format du certificat ("DER" ou "PEM")
     * @param filePath Chemin du fichier du certificat
     * @return Le certificat X509 chargé, ou null en cas d'erreur
     */
    public static X509Certificate chargerCertificat(String format, String filePath) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                System.err.println("Fichier introuvable : " + filePath);
                return null;
            }

            if (format.equalsIgnoreCase("DER")) {
                return ChargeCertificats.affichage_DER(filePath);
            } else if (format.equalsIgnoreCase("PEM")) {
                return ChargeCertificats.affichage_PEM(filePath);
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
    public static List<X509Certificate> chargerChaineCertificats(String format, String[] args) {
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
     * Charge un certificat X.509 au format DER depuis un fichier
     * @param filePath Chemin du fichier contenant le certificat au format DER
     * @return Un objet x509 Certificate ou une exception en cas d'erreur
     * @throws Exception S'il y a une erreur lors de la lecture du fichier
     */
    public static X509Certificate affichage_DER(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(filePath)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

    /**
     * Charge un certificat X.509 au format PEM depuis un fichier
     * @param filePath Chemin du fichier contenant le certificat au format PEM
     * @return Un objet x509 Certificate ou une exception en cas d'erreur
     * @throws Exception S'il y a une erreur lors de la lecture du fichier
     */
    public static X509Certificate affichage_PEM(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String pemContent = new String(Files.readAllBytes(Paths.get(filePath)));
        String base64Cert = pemContent.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(base64Cert);
        try (InputStream inStream = new ByteArrayInputStream(decoded)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }
}
