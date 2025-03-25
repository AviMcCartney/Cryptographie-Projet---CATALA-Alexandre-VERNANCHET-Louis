package org.example.Certificats.Utiles;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class OCSPManager {
    /**
     * Extrait l'URL OCSP depuis les extensions d'un certificat X.509
     * @param cert Le certificat X.509 contenant l'extension Authority Information Access
     * @return Un {@code Optional<String>} contenant l'URL OCSP si disponible, sinon {@code Optional.empty()}
     */
    public static Optional<String> extraireOCSPUrl(X509Certificate cert) {
        try {
            byte[] ocspExtensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (ocspExtensionValue == null) return Optional.empty();

            try (ASN1InputStream asn1Input = new ASN1InputStream(new ByteArrayInputStream(ocspExtensionValue))) {
                ASN1Primitive obj = asn1Input.readObject();
                ASN1OctetString octetString = ASN1OctetString.getInstance(obj);

                try (ASN1InputStream asn1Stream = new ASN1InputStream(octetString.getOctets())) {
                    AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(asn1Stream.readObject());

                    for (AccessDescription accessDesc : aia.getAccessDescriptions()) {
                        if (AccessDescription.id_ad_ocsp.equals(accessDesc.getAccessMethod())) {
                            GeneralName name = accessDesc.getAccessLocation();
                            if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                return Optional.of(name.getName().toString());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur extraction URL OCSP : " + e.getMessage());
        }
        return Optional.empty();
    }

    /**
     * Génère une requête OCSP pour vérifier le statut de révocation d'un certificat
     * @param cert Le certificat dont le statut doit être vérifié
     * @param issuerCert Le certificat de l'autorité de certification émettrice
     * @return Un tableau de bytes contenant la requête OCSP encodée, ou {@code null} en cas d'erreur
     */
    public static byte[] creerRequeteOCSP(X509Certificate cert, X509Certificate issuerCert) {
        try {
            //Création d'un calculateur de hachage SHA-1 requis pour OCSP
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                    .build().get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1"));

            //Génération de l'ID du certificat à vérifier
            CertificateID certID = new CertificateID(digestCalculator,
                    new JcaX509CertificateHolder(issuerCert), cert.getSerialNumber());

            //Création de la requête OCSP
            OCSPReq ocspRequest = new OCSPReqBuilder().addRequest(certID).build();
            return ocspRequest.getEncoded();

        } catch (Exception e) {
            System.err.println("Erreur création requête OCSP : " + e.getMessage());
            return null;
        }
    }

    /**
     * Envoie une requête OCSP à un serveur OCSP et analyse la réponse
     * @param ocspUrl L'URL du serveur OCSP
     * @param ocspRequestBytes La requête OCSP encodée
     * @return true si le certificat est révoqué, false sinon
     */
    public static boolean envoyerRequeteOCSP(String ocspUrl, byte[] ocspRequestBytes) {
        try {
            URL url = new URI(ocspUrl).toURL();
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);

            // Envoi de la requête OCSP
            try (OutputStream os = con.getOutputStream()) {
                os.write(ocspRequestBytes);
            }

            // Vérification du code HTTP
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                System.err.println("Erreur OCSP HTTP : " + con.getResponseCode());
                return false;
            }

            // Lecture et analyse de la réponse OCSP
            try (InputStream is = con.getInputStream();
                 ASN1InputStream asn1InputStream = new ASN1InputStream(is)) {

                OCSPResp ocspResp = new OCSPResp(OCSPResponse.getInstance(asn1InputStream.readObject()));
                if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                    System.err.println("Réponse OCSP invalide, code: " + ocspResp.getStatus());
                    return false;
                }

                BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
                if (basicResp == null) {
                    System.err.println("Impossible d'extraire la réponse OCSP.");
                    return false;
                }

                // Vérification du statut du certificat
                SingleResp[] responses = basicResp.getResponses();
                if (responses.length > 0) {
                    CertificateStatus certStatus = responses[0].getCertStatus();
                    return certStatus != CertificateStatus.GOOD;
                }
            }
        } catch (Exception e) {
            System.err.println("Erreur envoi requête OCSP : " + e.getMessage());
        }
        return false;
    }

}
