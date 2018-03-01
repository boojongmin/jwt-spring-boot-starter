//package com.example;
//
//import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.util.io.pem.PemObject;
//import org.bouncycastle.util.io.pem.PemReader;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.test.context.SpringBootTest;
//import org.springframework.test.context.TestPropertySource;
//import org.springframework.test.context.junit4.SpringRunner;
//import sun.security.util.Pem;
//
//import java.io.*;
//import java.security.*;
//import java.security.interfaces.RSAPrivateCrtKey;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.RSAPublicKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//
//@RunWith(SpringRunner.class)
//@SpringBootTest(classes= {JwtAutoConfiguration.class}, properties = {"classpath:test.yml"})
//public class JwtAutoConfigurationTest {
//    @Autowired private JwtProperties properties;
//
//    @Test
//    public void testProperties() throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
//        String privateKeyStr = properties.getRsa().getPrivateKey();
//        PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyStr.getBytes())));
//        Security.addProvider(new BouncyCastleProvider());
//
//        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
//        try {
//            byte[] content = pemReader.readPemObject().getContent();
//            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
//            PrivateKey privateKey = factory.generatePrivate(privateKeySpec);
//            RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
//            RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
//
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
//
//            System.out.println(privateKey);
//            System.out.println(publicKey);
//
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//    }
//
////    public static class PemFile {
////        private PemObject pemObject;
////
////        public PemFile(String privateKey) throws FileNotFoundException, IOException {
////            PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKey.getBytes())));
////            try {
////                this.pemObject = pemReader.readPemObject();
////            } finally {
////                pemReader.close();
////            }
////        }
////
////        public PemObject getPemObject() {
////            return pemObject;
////        }
////    }
////
//
//}
