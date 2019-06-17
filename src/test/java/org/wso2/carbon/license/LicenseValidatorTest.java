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
package org.wso2.carbon.license;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.wso2.carbon.license.exceptions.CarbonHomeException;
import org.wso2.carbon.license.exceptions.DecodeLicenseKeyException;
import org.wso2.carbon.license.exceptions.ProductCodeException;
import org.wso2.carbon.license.exceptions.PublicKeyException;
import org.wso2.carbon.license.exceptions.VerifyLicenseKeyException;

import java.nio.file.Paths;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertEquals;
import static org.wso2.carbon.license.utils.Constants.ALGORITHM_RSA;
import static org.wso2.carbon.license.utils.Constants.PRODUCT_CODES_CLAIM;

/**
 * Units test for LicenseValidator class methods.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(LicenseValidator.class)
public class LicenseValidatorTest {

    private String carbonHome = Paths.get(System.getProperty("parent.directory"), "/src/test/resources")
            .toString();
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private void setCarbonHomeProperty() {
        System.setProperty("carbon.home", carbonHome);
    }

    private void clearCarbonHome() {
        System.clearProperty("carbon.home");
    }

    @Test
    public void loadCarbonHome_HappyPath() throws Exception {
        setCarbonHomeProperty();
        String result = Whitebox.invokeMethod(LicenseValidator.class, "loadCarbonHome");
        assertEquals(carbonHome, result);
        clearCarbonHome();
    }

    @Test(expected = CarbonHomeException.class)
    public void loadCarbonHome_ExceptionThrown() throws Exception {
        clearCarbonHome();
        Whitebox.invokeMethod(LicenseValidator.class, "loadCarbonHome");
    }

    @Test
    public void getProductCode_HappyPath() throws Exception {
        String productCode = Whitebox.invokeMethod(LicenseValidator.class, "getProductCode",
                carbonHome + "/updates/product.txt");
        assertEquals("wso2is-km", productCode);
    }

    @Test
    public void getProductCode_ExceptionThrown() throws Exception {
        thrown.expect(ProductCodeException.class);
        thrown.expectMessage("Unable to read file: invalidFile");
        Whitebox.invokeMethod(LicenseValidator.class, "getProductCode", "invalidFile");
    }

    @Test
    public void getProductCode_NoDash_ProductCodeExceptionThrown() throws Exception {
        thrown.expect(ProductCodeException.class);
        thrown.expectMessage("Unable to parse product code");
        Whitebox.invokeMethod(LicenseValidator.class, "getProductCode",
                Paths.get(carbonHome, "/updates/product-incorrect.txt").toString());
    }
    @Test
    public void verifyLicenseKey_InvalidSignature_VerifyLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(VerifyLicenseKeyException.class);
        thrown.expectMessage("Signature is invalid");
        DecodedJWT decodedJWT = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInB" +
                "yb2R1Y3RDb2RlcyI6WyJ3c28yYW0iXX0.NPc8ghhf1dMCQofvUNir2KX5L4TKpZEL9Nua2rwl49rac4eN0aNT3iNXBbNXsk6r8" +
                "w-D1tjIILR6jobQzgQ18pTFxSIGbK2FQTwF_Dy8f_qwX2k7KWbh3eYnAcodjrQsSCaQitBy26dU2lq6TVbihnoGJ2lnI1PsHiU" +
                "oBeb0XJ3KvjktAoV0rxYm7NnLhoMUvGPcztBQpGw2n_LJspO7NBThKuIuo8yWRRKSqoEtCOTP1onrCHxWk5xXbASGerBajN6TI" +
                "f5Ylvs7rj4lY1wYhXRvsAAiO6LhbBEcLHbm-1sL2ldhrHJGkkN4av5U_CO99U2UeYaeWBYIFXYbPNDJQA");
        Whitebox.invokeMethod(LicenseValidator.class, "verifyLicenseKey",
                decodedJWT, carbonHome);
    }

    @Test
    public void verifyLicenseKey_Expired_VerifyLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(VerifyLicenseKeyException.class);
        thrown.expectMessage("License key has expired");
        DecodedJWT decodedJWT = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInBy" +
                "b2R1Y3RDb2RlcyI6WyJ3c28yaXMta20iXSwiZXhwIjoxNTYwNzk4MTAwfQ.jTjAJhevWKhrfXbEP8y4rfqJae8m4CuHYxjQWC6" +
                "HRQZeEObSG36R_xaovQrKQ1zIz8RfuMVcYUgwcXkQrUwu8gVvZWi8m5-G8S4crfkRkNlXfjETYmyYpUbWmDp7Tt9SvhYC9_bgx" +
                "qt9_L5ECg6WavP505yolDgV7Iknw36ZoweH2aw1pAow4MjsvvGcU4q6g1S8zDY1kLkbptJoEXn8cUiefz1cbtkkFxD1WNeicln" +
                "Iw9Io6YyijdhqHVcg0s3utXHBvH2ktWkMCzqoowRveulkPt8gcChs4Lu0XP48eQnLhoBgre9WSz5CWUgWnVElL2hod2z_iU7rE" +
                "L5AiC11mXzY9OhLdoKOlxRRqYSvd4i11H8_H9fHqdW3MpT4rcXK8OuOFec7jZy4vhw3Ap5GboSEJ0d-SK_SK9bULgqoraceM7m" +
                "8ML3FEet4bOn_M52Ju24tPuzWBatJE-avd7RC_W-xvwZsgg4CnIXpU2js4_qUlTOMA3tuClsTsaLrvOsOtSxkirrQKyF_PfIEh" +
                "NnfsxLiexIqdr2pDlxecdBHCAH-0zAbghGI9PczMVzxTCri_VmWGKAfOCgQQiOE-Z9RTa-NNSvteSTb9PH_Lmm5ARApTCCU52F" +
                "Yp_hof1WRjdz4iTt5hJfs3u4v_uQ4Pre3l0CeSIfL0LlAqAgfPGM4W68");
        Whitebox.invokeMethod(LicenseValidator.class, "verifyLicenseKey",
                decodedJWT, carbonHome);
    }

    @Test
    public void verifyLicenseKey_InvalidProductCode_VerifyLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(VerifyLicenseKeyException.class);
        thrown.expectMessage("Product code list doesn't contain the code: wso2is-km");
        DecodedJWT decodedJWT = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInBy" +
                "b2R1Y3RDb2RlcyI6WyJ3c28yYW0iXX0.dM16Neb_c1Nm45RU8oIFyWrsKcPMKQ1hE2uJ4KU_wQ5IT6P6_CjPefAUm7yfqMsknm" +
                "UdsRmoih364bNnZ7ao31wfJ9bQ17TpeF8M17mOXTkhRKhk06Ba6o4oogKgdJRe8FPza1txtCgMUQ7Qo0lYJHmyqS3NOrxWDI5" +
                "ny_wuzaVI7kVAjlqDQxkqmE6X_uz_ZoLGOd7tDj_65e3ZwScyGzbQd5R0C_FDxsdA0IG2vERHdZtQnwt9JI_rjQrOvxOtauLXZ" +
                "LicS2owKt2piRtkzcDdlr3F_SrCCYPS81A0rabCeRN2E5gAd3S9edJiLmEJ3r1NMZYQFOw6mQNfoVpo7aknH6Pn3mad0uxIOLL" +
                "LM7yCuuO_HC1EIVDRFdS30pD15p_oYmsj-bGB49ebqJ9kV824nfp9hEcAXl7EWjjmMkNRby4rt0HfWdKbVS-uuNGHEewgaLpXM" +
                "1swwElZRP_Ry72p8V0LdMxxdTYfEoSB_kaEVmmISLIeq94C0356iccZ82AWaA-o6MmVpMwwHbNd8mT88tm67x38L-2JslzrXzp" +
                "ikP3XRb3M4LULA2Wg7Tt9GTia_UlCa7BGZEgxlSbGaV7Ez59pCS-uQJZrS92q46rq--gpmliLlzEgrg1Wl0zAadn3yKKcxG6izw" +
                "Q3y5GxgQX5I9y92uukBULRRGhmnMk");
        Whitebox.invokeMethod(LicenseValidator.class, "verifyLicenseKey",
                decodedJWT, carbonHome);
    }

    @Test
    public void verifyLicenseKey_CorrectProductCode_HappyPath() throws Exception {
        DecodedJWT decodedJWT = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInB" +
                "yb2R1Y3RDb2RlcyI6WyJ3c28yaXMta20iXX0.lc0w8sJmSg4daHb5xGuUykq6nCEBuKmxCCvN0SBU7TC8jetT70VJv4hoGRQH3" +
                "n7WlPBxOdznXejLjnTBBHZaxNS-PF7jFkXyxpcJ-l5KdZvdRUr_TJulJ2hV5vmz_p2klXuFIjHz7IDT5ajU5BcBLpF_e8wqPs3" +
                "jMVAkPXSoQ2rgv19tFTfU6SbBVPNuicd7JpTPTzRHP2eAKZJ2VlWwcWo63sgz6TDLpOoo2gL0jKzrXxC1Nv77QQoQokq9H1hI2" +
                "YWtr1vSkDfe6TQDIrmBIpueZmV6Meu1xN2oFM3i5vyR42O2nRgeb7v3eCo0dLTbl8ZoZHEtvCo-CTf4lhXM0ywz0iIpuXlXHB" +
                "GxmZT1otNxAmBMgxtu_CsLwNKBrFnIKung5cp4ASA9GLLA5vkVF1I6SEMeiM232TEYueGolm9PqqG_tGpGSJLS0VZRgUakhxX9" +
                "o2CYnzOSMLteMrEBOfpsg6w7KOEJ0FIJxhKvxrz-zYCrXgcTJmsUQlM1mBeGUcpeQlmukQ8_0EbhZVZ0BS3BadnD8ZEgdYKoc" +
                "5X8eTqqJ8xXd5qcUaMFqWq-luiteOGvj1RIMcJAGtmTExTYjXHGnkpCMGV9n0pZ9hpQbya5vhOPB7y9Mifj6Hj9VxIRP0PjZn" +
                "GQhB_ZuFNKOeAp3LmSuOm7FMbT-_w1FxDvVHk");
        Whitebox.invokeMethod(LicenseValidator.class, "verifyLicenseKey",
                decodedJWT, carbonHome);
    }

    @Test
    public void verifyLicenseKey_WSO2CarbonCode_HappyPath() throws Exception {
        DecodedJWT decodedJWT = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIs" +
                "InByb2R1Y3RDb2RlcyI6WyJ3c28yY2FyYm9uIl19.viaR6RBydShtaelrlrZObcXESvm4NC0weiY0yANFxNwtWuD9ktdySN0k" +
                "hyPTrw3M1rgJgP_pbaBQcD-MDRvVsosftVIGbpn1sEMuqWaNShvNaUhWl2LCvNz_ipaTlEXr6BYTsZEDo-z3V1ivJfDXCBzzXC" +
                "wxR7VuLtumbJOBZYGzyNr2cxcEGCeyeUVCQNQo_iow7IkHGwoKejQtmYLOKR2Sz6NFBogvSfWVwUXCUZ7AbgVmz4_Scfg8vzMQ" +
                "1dR9Vnn6UFuw3a5Wwiuw9b8aCcLjiN8c22pR21evknnUBycusu8OeRyyVNoSLzbfenHq8vQB0vFVggmx5mjl60cx6jey_6wMS3m" +
                "Nc-iD-blxuvoyhVq3jSnefUT9kgkgnPp3QKfkiF4JoLJdqKmZu2agMz61sTLsXghANaS5jWhFtJ7Ziwm0NfDvTHGLzz9n8SDr8f" +
                "x41bgg39H_gjsG8WDnl26_RYJpvNihrRVabb58EPLyQyheii0bU9_A7X91kvjnpZkg_VZy5Q9kTPoAMfywLqekgxpUC3VX2hOvq" +
                "dXh30Bbf72JeNeoZ9JSF2V5S6S7yG7dXC4Sj_iha06oP2zmlQ3NWSUknnHlHvlJ8ho4u6DPh5l6iytriVH-YoLvIRk20Hw4MZk9" +
                "-rpfmgyrItN5tzYshFojmv9V112yuJqfY84");
        Whitebox.invokeMethod(LicenseValidator.class, "verifyLicenseKey",
                decodedJWT, carbonHome);
    }

    @Test
    public void getRSAPublicKey_HappyPath() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(LicenseValidatorTest.class.getClassLoader()
                .getResourceAsStream("certs/public_key.der"))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        RSAPublicKey result = Whitebox.invokeMethod(LicenseValidator.class, "getRSAPublicKey");
        assertEquals(result.getAlgorithm(), ALGORITHM_RSA);
    }

    @Test
    public void getRSAPublicKey_PublicKeyExceptionThrown() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(LicenseValidatorTest.class.getClassLoader()
                .getResourceAsStream("certs/public_key_incorrect.pem"))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        thrown.expect(PublicKeyException.class);
        thrown.expectMessage("Invalid public key");
        Whitebox.invokeMethod(LicenseValidator.class, "getRSAPublicKey");
    }

    @Test
    public void decodeLicenseKey_InvalidPath_DecodeLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(DecodeLicenseKeyException.class);
        thrown.expectMessage(String.format("Unable to read license key file: %s", carbonHome + "/tokens/invalid"));
        Whitebox.invokeMethod(LicenseValidator.class, "decodeLicenseKey", carbonHome + "/tokens/invalid");
    }

    @Test
    public void decodeLicenseKey_NoExpireDate_dDecodeLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(DecodeLicenseKeyException.class);
        thrown.expectMessage("Expire data is not defined");
        Whitebox.invokeMethod(LicenseValidator.class, "decodeLicenseKey", carbonHome + "/tokens/expired");
    }

    @Test
    public void decodeLicenseKey_NoIssuer_dDecodeLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(DecodeLicenseKeyException.class);
        thrown.expectMessage("Issuer claim is not defined");
        Whitebox.invokeMethod(LicenseValidator.class, "decodeLicenseKey", carbonHome + "/tokens/no-issuer");
    }

    @Test
    public void decodeLicenseKey_NoProductCodeClaim_dDecodeLicenseKeyExceptionThrown() throws Exception {
        thrown.expect(DecodeLicenseKeyException.class);
        thrown.expectMessage(String.format("%s claim is not configured or empty",
                PRODUCT_CODES_CLAIM));
        Whitebox.invokeMethod(LicenseValidator.class, "decodeLicenseKey", carbonHome + "/tokens/no-product-code-claim");
    }

    @Test
    public void decodeLicenseKey_HappyPath() throws Exception {
        Whitebox.invokeMethod(LicenseValidator.class, "decodeLicenseKey", carbonHome + "/tokens/valid");
    }
}
