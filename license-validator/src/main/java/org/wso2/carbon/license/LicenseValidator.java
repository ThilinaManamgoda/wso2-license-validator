/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.license;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.wso2.carbon.license.exceptions.CarbonHomeException;
import org.wso2.carbon.license.exceptions.DecodeLicenseKeyException;
import org.wso2.carbon.license.exceptions.ProductCodeException;
import org.wso2.carbon.license.exceptions.PublicKeyException;
import org.wso2.carbon.license.exceptions.VerifyLicenseKeyException;
import org.wso2.carbon.license.utils.Constants;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import static org.wso2.carbon.license.utils.Constants.ALGORITHM_RSA;
import static org.wso2.carbon.license.utils.Constants.LICENSE_KEY_PATH;
import static org.wso2.carbon.license.utils.Constants.PRODUCT_CODES_CLAIM;
import static org.wso2.carbon.license.utils.Constants.PRODUCT_FILE_PATH;
import static org.wso2.carbon.license.utils.Constants.PUBLIC_KEY;
import static org.wso2.carbon.license.utils.Constants.WSO2_CARBON_CODE;

/**
 * This class validates the license key.
 * <p>
 * This class holds the "premain" method of the Java agent. This method reads the license
 * key file located at {Carbon Home}/{@link Constants#LICENSE_KEY_PATH} and validate against,
 * 1. Issuer
 * 2. Expire date
 * 3. {@link Constants#PRODUCT_CODES_CLAIM}
 * 4. Signature
 *
 * @since 1.0.0
 */
public class LicenseValidator {

    private static final Logger logger = Logger.getLogger(LicenseValidator.class.getName());

    /**
     * After the Java Virtual Machine (JVM) has initialized,  premain method will be called. This method will load
     * the license key and validate followings,
     * <p>
     * 1. Issuer
     * 2. Expire date
     * 3. {@link Constants#PRODUCT_CODES_CLAIM}
     * 4. Signature
     *
     * @param agentArgument Argument passed for the Java agent
     */
    public static void premain(@SuppressWarnings("unused") final String agentArgument) {
        String carbonHome = null;
        try {
            carbonHome = loadCarbonHome();
            DecodedJWT decodedJWT = decodeLicenseKey(Paths.get(carbonHome, LICENSE_KEY_PATH).toString());
            verifyLicenseKey(decodedJWT, carbonHome);
        } catch (Throwable e) {
            handleError(e, carbonHome);
        }
    }

    /**
     * Returns an Input stream for the Public cert file in the resources/{@link Constants#PUBLIC_KEY}.
     *
     * @return {@link InputStream}
     */
    private static InputStream getPublicKeyFileStream() {
        return LicenseValidator.class.getClassLoader().getResourceAsStream(PUBLIC_KEY);

    }

    /**
     * Load public certificate in .pem format as a {@link RSAPublicKey}.
     *
     * @return public key {@link RSAPublicKey}
     * @throws PublicKeyException If cannot construct the public certificate
     */
    private static RSAPublicKey getRSAPublicKey() throws PublicKeyException {
        byte[] fileContent;
        try (InputStream inputStream = getPublicKeyFileStream();
             ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = inputStream.read(buffer)) != -1) {
                byteArrayOutputStream.write(buffer, 0, len);
            }
            byteArrayOutputStream.flush();
            fileContent = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            String errMsg = String.format("Couldn't load the public key file: %s", PUBLIC_KEY);
            throw new PublicKeyException(errMsg, e);
        }
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(fileContent);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(ALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new PublicKeyException(String.format("Couldn't find the algorithm %s", ALGORITHM_RSA), e);
        }
        RSAPublicKey publicKey;
        try {
            publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        } catch (InvalidKeySpecException e) {
            throw new PublicKeyException("Invalid public key", e);
        }
        return publicKey;
    }

    /**
     * This method reads the license key from the given file and construct a JWT if the following claims are
     * present,
     * 1. Issuer
     * 2. Expire date
     * 3. {@link Constants#PRODUCT_CODES_CLAIM}
     *
     * @param licenseKeyPath Path to the license key file
     * @return Decoded JWT token {@link DecodedJWT}
     * @throws DecodeLicenseKeyException If the JWT is not valid
     */
    private static DecodedJWT decodeLicenseKey(String licenseKeyPath) throws DecodeLicenseKeyException {
        byte[] fileContent;
        try {
            fileContent = Files.readAllBytes(Paths.get(licenseKeyPath));
        } catch (IOException e) {
            throw new DecodeLicenseKeyException(String.format("Unable to read license key file: %s",
                    licenseKeyPath), e);
        }
        String jwtString = new String(fileContent, StandardCharsets.UTF_8);
        DecodedJWT decodedJWT = JWT.decode(jwtString);
        if (decodedJWT.getIssuer() == null) {
            throw new DecodeLicenseKeyException("Issuer claim is not defined");
        }
        if (decodedJWT.getExpiresAt() == null) {
            throw new DecodeLicenseKeyException("Expire data is not defined");
        }
        String[] jwtProductCodes = decodedJWT.getClaim(PRODUCT_CODES_CLAIM).asArray(String.class);
        if (jwtProductCodes == null || jwtProductCodes.length == 0) {
            throw new DecodeLicenseKeyException(String.format("%s claim is not configured or empty",
                    PRODUCT_CODES_CLAIM));
        }
        return decodedJWT;
    }

    /**
     * Verifies following JWT claims.
     * <p>
     * 1. Signature
     * 2. Expire date
     * 3. The Product code claim is valid if the product code or "wso2carbon" is with in
     * the jwt claim {@link Constants#PRODUCT_CODES_CLAIM}.
     * 4. Issuer
     * <p>
     * Assumption: Decoded JWT has {@link Constants#PRODUCT_CODES_CLAIM} & "exp" claims
     *
     * @param decodedJWT Decode JWT
     * @throws PublicKeyException        If cannot construct the public certificate
     * @throws VerifyLicenseKeyException If the token is invalid
     * @throws ProductCodeException      if unable to read the given file or get product code
     */
    private static void verifyLicenseKey(final DecodedJWT decodedJWT, final String carbonHome)
            throws PublicKeyException, VerifyLicenseKeyException, ProductCodeException {

        Algorithm algorithm = Algorithm.RSA256(getRSAPublicKey(), null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(Constants.ISSUER)
                .build();
        // Verify Expire date + signature
        try {
            verifier.verify(decodedJWT);
        } catch (TokenExpiredException e) {
            throw new VerifyLicenseKeyException("License key has expired", e);
        } catch (InvalidClaimException e) {
            throw new VerifyLicenseKeyException("Issuer is invalid", e);
        } catch (JWTVerificationException e) {
            throw new VerifyLicenseKeyException("Signature is invalid", e);
        }
        // Verify product code
        String productCode = getProductCode(Paths.get(carbonHome, PRODUCT_FILE_PATH).toString());
        String[] jwtProductCodes = decodedJWT.getClaim(PRODUCT_CODES_CLAIM).asArray(String.class);
        for (String jwtProductCode : jwtProductCodes) {
            if (jwtProductCode.equals(productCode) || jwtProductCode.equals(WSO2_CARBON_CODE)) {
                return;
            }
        }
        throw new VerifyLicenseKeyException(String.format("Product code list doesn't contain the code: %s",
                productCode));
    }

    /**
     * Loads the "carbon.home" property value.
     *
     * @return Carbon home
     * @throws CarbonHomeException If "carbon.home" property is not configured
     */
    private static String loadCarbonHome() throws CarbonHomeException {
        String carbonHome = System.getProperty(Constants.CARBON_HOME);
        if (carbonHome == null) {
            throw new CarbonHomeException(String.format("Property: %s is not configured",
                    Constants.CARBON_HOME));
        }
        return carbonHome;
    }

    /**
     * Reads the product code from given file.
     *
     * @param productFilePath Path of the product code file
     * @return Product code
     * @throws ProductCodeException if unable to read the given file or get product code
     */
    private static String getProductCode(final String productFilePath) throws ProductCodeException {
        String fileContent;
        try {
            fileContent = new String(Files.readAllBytes(Paths.get(productFilePath))
                    , StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ProductCodeException(String.format("Unable to read file: %s",
                    productFilePath), e);
        }
        int lastIndexOfDash = fileContent.lastIndexOf("-");
        if (lastIndexOfDash == -1) {
            throw new ProductCodeException("Unable to parse product code");
        }
        return fileContent.substring(0, lastIndexOfDash);
    }

    /**
     * Log the error and exit with exit code 1.
     *
     * @param err        Throwable error
     * @param carbonHome Carbon Home
     */
    private static void handleError(Throwable err, String carbonHome) {
        String runtimeHome = System.getProperty(Constants.RUNTIME_HOME);
        String logFilePath;
        if (runtimeHome != null) {
            logFilePath = Paths.get(runtimeHome, "/logs/validator.log").toString();
        } else {
            logFilePath = Paths.get(carbonHome, "/repository/logs/validator.log").toString();
        }
        try {
            FileHandler fileHandler = new FileHandler(logFilePath);
            fileHandler.setLevel(Level.SEVERE);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
        } catch (IOException e) {
            System.err.println(e);
            System.exit(Constants.EXIT_CODE_2);
        }
        logger.log(Level.SEVERE, err.getMessage(), err);
        System.exit(Constants.EXIT_CODE_1);
    }
}
