import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

public class ValidateCert {
    public static X509Certificate affichage_DER(String filePath) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (InputStream inStream = new FileInputStream(filePath)) {
            return (X509Certificate) certFactory.generateCertificate(inStream);
        }
    }

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

    public static boolean verifierSignature(X509Certificate cert) {
        try {
            PublicKey publicKey = cert.getPublicKey();
            cert.verify(publicKey);
            return true;
        } catch (Exception e) {
            System.err.println("Échec de la vérification de la signature: " + e.getMessage());
            return false;
        }
    }

    public static void verifierKeyUsage(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            System.out.println("Key Usage:");
            String[] usages = {"Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only", "Decipher Only"};
            for (int i = 0; i < keyUsage.length; i++) {
                if (keyUsage[i]) {
                    System.out.println("✔ " + usages[i]);
                }
            }
        } else {
            System.out.println("Key Usage non spécifié dans le certificat.");
        }
    }
}
