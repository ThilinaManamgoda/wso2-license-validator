/*
 *  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.wso2.exceptions.InvalidCarbonHomeException;
import org.wso2.exceptions.InvalidLicenseFileException;
import org.wso2.exceptions.InvalidLicenseKeyException;
import org.wso2.exceptions.InvalidProductCodeException;
import org.wso2.exceptions.InvalidPublicKeyException;
import org.wso2.exceptions.LicenseKeyExpiredException;
import org.wso2.utils.Constants;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import static org.wso2.utils.Constants.ALGORITHM;
import static org.wso2.utils.Constants.LICENSE_KEY_PATH;
import static org.wso2.utils.Constants.PRODUCT_CODES_CLAIM;
import static org.wso2.utils.Constants.PRODUCT_FILE_PATH;
import static org.wso2.utils.Constants.PUBLIC_KEY;
import static org.wso2.utils.Constants.WSO2_CARBON_CODE;

/**
 * This class validates the license key.
 */
public class LicenseValidator {

    private static final Logger logger = Logger.getLogger(LicenseValidator.class.getName());
    private static String carbonHome;

    /**
     * The agent class must implement a public static premain method similar in principle to the main application
     * entry point. After the Java Virtual Machine (JVM) has initialized, each premain method will be called in the
     * order the agents were specified.
     *
     * @param agentArgument Argument passed for the Java agent
     */
    public static void premain(final String agentArgument) {
        try {
            loadCarbonHome();
            DecodedJWT decodedJWT = verify(carbonHome + LICENSE_KEY_PATH);
            inspectExpireDate(decodedJWT);
            validateProductCode(decodedJWT);
        } catch (TokenExpiredException e) {
            handleError(new LicenseKeyExpiredException("License key has expired", e));
        } catch (JWTVerificationException e) {
            handleError(new InvalidLicenseKeyException("Invalid license key", e));
        } catch (InvalidKeySpecException e) {
            handleError(new InvalidPublicKeyException(String.format("Invalid public key: %s", PUBLIC_KEY), e));
        } catch (IOException e) {
            String errMsg = String.format("Couldn't load the public key file: %s", PUBLIC_KEY);
            handleError(new InvalidPublicKeyException(errMsg, e));
        } catch (Throwable e) {
            handleError(e);
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
     * @throws IOException              If cannot read the public certificate
     * @throws NoSuchAlgorithmException If cannot find the algorithm "RSA"
     * @throws InvalidKeySpecException  If cannot create public key
     */
    private static RSAPublicKey getRSAPublicKey() throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        StringBuilder sb = new StringBuilder();
        try (InputStream inputStream = getPublicKeyFileStream();
             BufferedReader buf = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line = buf.readLine();
            while (line != null) {
                sb.append(line);
                line = buf.readLine();
            }
        }
        String publicKeyContent = sb.toString()
                .replaceAll("\\n", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return (RSAPublicKey) kf.generatePublic(keySpecX509);
    }

    /**
     * Verify JWT. The token will be invalid if the following condition are true,
     * 1. Token has expired
     * 2. If the issuer doesn't match
     * 3. The signature is invalid
     * 4. Invalid issuer
     * This method will read the license key from the file.
     *
     * "{@link LicenseValidator#carbonHome}/{@link Constants#LICENSE_KEY_PATH}".
     *
     * @param licenseKeyPath Path to the license key file
     * @return Decoded JWT token {@link DecodedJWT}
     * @throws NoSuchAlgorithmException If cannot find the algorithm "RSA"
     * @throws IOException              If cannot read the public certificate
     * @throws InvalidKeySpecException  If cannot create public key
     * @throws JWTVerificationException If the JWT is not valid
     */
    private static DecodedJWT verify(String licenseKeyPath) throws NoSuchAlgorithmException, IOException,
            InvalidKeySpecException, JWTVerificationException, InvalidLicenseFileException {
        byte[] fileContent;
        try {
            fileContent = Files.readAllBytes(Paths.get(licenseKeyPath));
        } catch (IOException e) {
            throw new InvalidLicenseFileException(String.format("Unable to read license key file: %s",
                    licenseKeyPath), e);
        }
        String jwt = new String(fileContent, StandardCharsets.UTF_8);
        Algorithm algorithm = Algorithm.RSA256(getRSAPublicKey(), null);
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(Constants.ISSUER)
                .build();
        return verifier.verify(jwt);
    }

    /**
     * Loads the carbon.home property value in to carbonHome.
     *
     * @throws InvalidCarbonHomeException If "carbon.home" property is not configured or empty
     */
    private static void loadCarbonHome() throws InvalidCarbonHomeException {
        carbonHome = System.getProperty(Constants.CARBON_HOME);
        if (carbonHome == null) {
            throw new InvalidCarbonHomeException(String.format("Property: %s is not configured",
                    Constants.CARBON_HOME));
        }
    }

    /**
     * Reads the product code from "${CARBON_HOME}/updates/product.txt".
     *
     * @return Product code
     * @throws InvalidProductCodeException if unable to read the product.txt
     */
    private static String getProductCode() throws InvalidProductCodeException {
        String productCode;
        try {
            String fileContent = new String(Files.readAllBytes(Paths.get(carbonHome + PRODUCT_FILE_PATH))
                    , StandardCharsets.UTF_8);
            productCode = fileContent.substring(0, fileContent.lastIndexOf("-"));
        } catch (IOException e) {
            throw new InvalidProductCodeException(String.format("Unable to read file %s",
                    carbonHome + PRODUCT_FILE_PATH), e);
        }
        return productCode;
    }

    /**
     * Log the error and exit with exit code 1.
     *
     * @param err Throwable error
     */
    private static void handleError(Throwable err) {
        Handler handlerObj = new ConsoleHandler();
        handlerObj.setLevel(Level.SEVERE);
        logger.addHandler(handlerObj);
        logger.log(Level.SEVERE, err.getMessage(), err);
        System.exit(Constants.EXIT_CODE);
    }

    /**
     * Validates the Product code claim. The Product code claim is valid if the code in product.txt is with in the
     * given product code list or equal to "wso2carbon".
     *
     * @param jwt JWT token
     * @throws InvalidProductCodeException If ${CARBON_HOME} is not set, unable to read the product.txt
     *                                     or product code doesn't match
     */
    private static void validateProductCode(final DecodedJWT jwt) throws InvalidProductCodeException {
        String[] jwtProductCodes = jwt.getClaim(PRODUCT_CODES_CLAIM).asArray(String.class);
        if (jwtProductCodes == null || jwtProductCodes.length == 0) {
            throw new InvalidProductCodeException(String.format("%s claim is not configured or em[ty",
                    PRODUCT_CODES_CLAIM));
        }
        String productCode = getProductCode();
        for (String jwtProductCode : jwtProductCodes) {
            if (jwtProductCode.equals(productCode) || jwtProductCode.equals(WSO2_CARBON_CODE)) {
                return;
            }
        }
        throw new InvalidProductCodeException(String.format("Invalid product codes: %s", productCode));
    }

    /**
     * Check whether the "exp" claim is set or not.
     *
     * @param jwt JWT token
     * @throws LicenseKeyExpiredException If the "exp" claim is set
     */
    private static void inspectExpireDate(final DecodedJWT jwt) throws LicenseKeyExpiredException {
        if (jwt.getExpiresAt() == null) {
            throw new LicenseKeyExpiredException("Expire data is not defined");
        }
    }
}
