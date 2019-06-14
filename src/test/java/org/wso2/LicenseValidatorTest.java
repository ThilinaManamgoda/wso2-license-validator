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
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.wso2.exceptions.InvalidCarbonHomeException;
import org.wso2.exceptions.InvalidLicenseFileException;
import org.wso2.exceptions.InvalidProductCodeException;
import org.wso2.exceptions.LicenseKeyExpiredException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertEquals;
import static org.wso2.utils.Constants.ALGORITHM;
import static org.wso2.utils.Constants.PUBLIC_KEY;

/**
 * Units test for LicenseValidator class methods.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(LicenseValidator.class)
public class LicenseValidatorTest {

    private String carbonHome = System.getProperty("parent.directory") + "/src/test/resources";

    private void setCarbonHomeProperty() {
        System.setProperty("carbon.home", carbonHome);
    }

    private void setCarbonHome() {
        Whitebox.setInternalState(LicenseValidator.class,
                "carbonHome", carbonHome);
    }

    private void clearCarbonHome() {
        System.clearProperty("carbon.home");
        Whitebox.setInternalState(LicenseValidator.class, "carbonHome", "");
    }

    @Test
    public void loadCarbonHome_HappyPath() throws Exception {
        setCarbonHomeProperty();
        Whitebox.invokeMethod(LicenseValidator.class, "loadCarbonHome");
        assertEquals(carbonHome, Whitebox.getInternalState(LicenseValidator.class, "carbonHome"));
        clearCarbonHome();
    }

    @Test(expected = InvalidCarbonHomeException.class)
    public void loadCarbonHome_ExceptionThrown() throws Exception {
        clearCarbonHome();
        Whitebox.invokeMethod(LicenseValidator.class, "loadCarbonHome");
    }

    @Test
    public void getProductCode_HappyPath() throws Exception {
        Whitebox.setInternalState(LicenseValidator.class, "carbonHome", carbonHome);
        String productCode = Whitebox.invokeMethod(LicenseValidator.class, "getProductCode");
        assertEquals("wso2is-km", productCode);
    }

    @Test(expected = InvalidProductCodeException.class)
    public void getProductCode_ExceptionThrown() throws Exception {
        clearCarbonHome();
        Whitebox.invokeMethod(LicenseValidator.class, "getProductCode");
    }

    @Test
    public void getRSAPublicKey_HappyPath() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(LicenseValidatorTest.class.getClassLoader().getResourceAsStream(PUBLIC_KEY))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        RSAPublicKey key = Whitebox.invokeMethod(LicenseValidator.class, "getRSAPublicKey");
        assertEquals(ALGORITHM, key.getAlgorithm());
    }

    @Test(expected = IOException.class)
    public void getRSAPublicKey_IOExceptionThrown() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(new FileInputStream(""))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        Whitebox.invokeMethod(LicenseValidator.class, "getRSAPublicKey");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getRSAPublicKey_InvalidKeyExceptionThrown() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(LicenseValidatorTest.class.getClassLoader()
                .getResourceAsStream("certs/public_key_incorrect.pem"))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        Whitebox.invokeMethod(LicenseValidator.class, "getRSAPublicKey");
    }

    @Test
    public void validateProductCode_HappyPath() throws Exception {
        setCarbonHome();
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInByb2R1Y3RD" +
                "b2RlcyI6WyJ3c28yaXMta20iXX0.lc0w8sJmSg4daHb5xGuUykq6nCEBuKmxCCvN0SBU7TC8jetT70VJv4hoGRQH3n7WlPBxOdz" +
                "nXejLjnTBBHZaxNS-PF7jFkXyxpcJ-l5KdZvdRUr_TJulJ2hV5vmz_p2klXuFIjHz7IDT5ajU5BcBLpF_e8wqPs3jMVAkPXSoQ2" +
                "rgv19tFTfU6SbBVPNuicd7JpTPTzRHP2eAKZJ2VlWwcWo63sgz6TDLpOoo2gL0jKzrXxC1Nv77QQoQokq9H1hI2YWtr1vSkDfe6" +
                "TQDIrmBIpueZmV6Meu1xN2oFM3i5vyR42O2nRgeb7v3eCo0dLTbl8ZoZHEtvCo-CTf4lhXM0ywz0iIpuXlXHBGxmZT1otNxAmBM" +
                "gxtu_CsLwNKBrFnIKung5cp4ASA9GLLA5vkVF1I6SEMeiM232TEYueGolm9PqqG_tGpGSJLS0VZRgUakhxX9o2CYnzOSMLteMrE" +
                "BOfpsg6w7KOEJ0FIJxhKvxrz-zYCrXgcTJmsUQlM1mBeGUcpeQlmukQ8_0EbhZVZ0BS3BadnD8ZEgdYKoc5X8eTqqJ8xXd5qcUa" +
                "MFqWq-luiteOGvj1RIMcJAGtmTExTYjXHGnkpCMGV9n0pZ9hpQbya5vhOPB7y9Mifj6Hj9VxIRP0PjZnGQhB_ZuFNKOeAp3LmSu" +
                "Om7FMbT-_w1FxDvVHk");
        Whitebox.invokeMethod(LicenseValidator.class, "validateProductCode", jwt);
        clearCarbonHome();
    }

    @Test
    public void validateProductCode_WSO2CarbonCode() throws Exception {
        setCarbonHome();
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInByb2R1Y" +
                "3RDb2RlcyI6WyJ3c28yaXMta20iLCJ3c28yY2FyYm9uIl19.Ra2T1npi5Xli5ZqrfPDA0I2T3AmQpNuVc4c-R29FFI9Smm-a" +
                "4LvMI4ocXwUhs6FVM9ad5uMRL5VU9i_PuGVKSL_wr6RIExJZvHqOOySgknVFgsEnIMuSFX1C_VuNsMsyF7KLO_T4lakGTNtD" +
                "PqReKIgV80WS9AoqPBVMgND3nXrmlb8SwJi15fbELNZYD6OIgM2lNTZYVzCBn-jrBHU0PLuM_-eWqWu5LXjPqZW8vmapeiN9" +
                "wNCnA4HbwMbomN4IiTnGVOwAPHjGh2JuqDRrM34nhKrE5xXKZd19_ekzDHJh1bsLhQEi9U8ycSV7oLDCKJ_UOSwELKnq_upi" +
                "xSnLVImV7_y2jZwksdr7fFHxsWzECQvRFgrmGyyBNXJ19kfpVGxdTb58d1WyeyQEcPy6SBHwNj5qGi3dq5D7JK67rLSO45lu" +
                "xLj0jjkMKKRdHgBvksOv-HGUWq_duSGx-3hnwVmmLAD9FgXOVyED1kcpBg7skBrXBd42yaboq3ANhNhO9BZOm1_Anc7MDrL7" +
                "X7PzgIpJAr9ca_BqKoAjOpxTocloSsCH-4E_-fxxABcHGYpbhVha7oMz-HjcGD8OeXMNoUzQ0QC3ocn8mXEqv30y3f2rzETC" +
                "M27srKF9VNR2FryEqoMOu5uZI2EZKjpd6_50LZRWivZZTo1KSU-IUe6099c");
        Whitebox.invokeMethod(LicenseValidator.class, "validateProductCode", jwt);
        clearCarbonHome();
    }

    @Test(expected = InvalidProductCodeException.class)
    public void validateProductCode_InvalidProductCodeExceptionThrown() throws Exception {
        setCarbonHome();
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSIsInByb2R1Y" +
                "3RDb2RlcyI6WyJ3c28yYW0iXX0.dM16Neb_c1Nm45RU8oIFyWrsKcPMKQ1hE2uJ4KU_wQ5IT6P6_CjPefAUm7yfqMsknmUds" +
                "moih364bNnZ7ao31wfJ9bQ17TpeF8M17mOXTkhRKhk06Ba6o4oogKgdJRe8FPza1txtCgMUQ7Qo0lYJHmyqS3NOrxWDI5ny_w" +
                "uzaVI7kVAjlqDQxkqmE6X_uz_ZoLGOd7tDj_65e3ZwScyGzbQd5R0C_FDxsdA0IG2vERHdZtQnwt9JI_rjQrOvxOtauLXZLic" +
                "S2owKt2piRtkzcDdlr3F_SrCCYPS81A0rabCeRN2E5gAd3S9edJiLmEJ3r1NMZYQFOw6mQNfoVpo7aknH6Pn3mad0uxIOLLLM7y" +
                "CuuO_HC1EIVDRFdS30pD15p_oYmsj-bGB49ebqJ9kV824nfp9hEcAXl7EWjjmMkNRby4rt0HfWdKbVS-uuNGHEewgaLpXM1swwE" +
                "lZRP_Ry72p8V0LdMxxdTYfEoSB_kaEVmmISLIeq94C0356iccZ82AWaA-o6MmVpMwwHbNd8mT88tm67x38L-2JslzrXzpikP3X" +
                "Rb3M4LULA2Wg7Tt9GTia_UlCa7BGZEgxlSbGaV7Ez59pCS-uQJZrS92q46rq--gpmliLlzEgrg1Wl0zAadn3yKKcxG6izwQ3y5" +
                "GxgQX5I9y92uukBULRRGhmnMk");
        Whitebox.invokeMethod(LicenseValidator.class, "validateProductCode", jwt);
        clearCarbonHome();
    }

    @Test(expected = InvalidProductCodeException.class)
    public void validateProductCode_NullProductCode_InvalidProductCodeExceptionThrown() throws Exception {
        setCarbonHome();
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yLmNvbSJ9.jJHSwz" +
                "okQWPkLG4h2tSPNOA6fJ5xacYqTeDFAi8Pb68OvUeIwBYGKk12FO83K0XYwncN42J7EdpdAs-78opxOwWoTJ_gKJoyn3AK" +
                "_orQw0Gq2HRbQCB-86Nd3ulnuLJTH1mvnPOSv3odnl0m6gYPBWX5r2s9KCpkVz0y20EXHMPWQ4lEEkEy9Ee-pxtVzpY00f" +
                "Cq1bdXwdvxNDleMCKqZuKtwaYDPyJdRfwoIa1vJkuwpLpKEmLe_oTrWHEup2MkJXhbfnhTApaw1uoTvsfFFpuEFPTr2UEsR" +
                "vGeZgF_Rk8zD23iTyQIgkfCrKcq61wuoSBRYVkHC_aiRF_sjstWxkj3Ytb6gixvZh_jJY3rfNcFkpgQPrfeLoFxDOyadlqX" +
                "u3zjO5ISUoGYxFO9DtVeTdpZfacQBlQN0KK1cHnLTD5NDJR-zd1RJn8C3M22-Lg3d133rVHBePWV2y3QlPd5c4yT6GF6n5U" +
                "5J7x8VoiMAt5747IgxfquVeYDwQKkLLG0eNOz5GDAalO4atIVOinXomrbEvn1iIcQ7iGFGJTiw65aCX1uCgP5bMHExhpDPg" +
                "1BX_j3mQKPowkV1LyvUyFDA-bikd0WJ5szlc3MbejG-GgKWvhPd3FYE9S0h1KSQX5-JAPvAaytgSROyXMc6snCk1Clly52n" +
                "7nkzo6Dgq1as_Q");
        Whitebox.invokeMethod(LicenseValidator.class, "validateProductCode", jwt);
        clearCarbonHome();
    }

    @Test
    public void verify_HappyPath() throws Exception {
        PowerMockito.spy(LicenseValidator.class);
        PowerMockito.doReturn(LicenseValidatorTest.class.getClassLoader()
                .getResourceAsStream("certs/public.pem"))
                .when(LicenseValidator.class, "getPublicKeyFileStream");
        Whitebox.invokeMethod(LicenseValidator.class, "verify", carbonHome + "/token/valid");
    }


    @Test(expected = InvalidLicenseFileException.class)
    public void verify_InvalidLicenseFileExceptionThrown() throws Exception {
        Whitebox.invokeMethod(LicenseValidator.class, "verify", carbonHome + "/token/invalid");
    }

    @Test(expected = JWTVerificationException.class)
    public void verify_JWTVerificationExceptionExceptionThrown() throws Exception {
        Whitebox.invokeMethod(LicenseValidator.class, "verify", carbonHome + "/token/expired");
    }

    @Test
    public void inspectExpireDate_HappyPath() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yIiwicHJvZHVjdENvZGVz" +
                "Ijoid3NvMmlzLWttIiwiZXhwIjoxNTYwNTA1NTU5fQ.b8Ik9fBWY5ngPYJEsQYrySEx7op9fVSNcmoo398Baffl76TwKXvFWVT" +
                "_s3vOP5K7kuV-_L7SaBgLN1bT1J6B0luUdiYHE8p-cMIccqB7qT3yCjE_plF58EsQlZQSBtP4P2Tq1FcvtoBbP5Ui1oOrnMlxZ" +
                "W4W0vkfyTlbdqDx89d9pmnrA6jSbwkcZOZFCRZf7rSqnsRuvtXJxOc-lb7_8iWqAMVYRCfo_GKAdEfrajazBV0CoZ44EDcoD1z" +
                "h5fdvRH5GpEoK-4Qt7vsmoWZoOT_dLJkhiHPiU4_SN202A3bSOPqpjHg8gX_LLAO8LiHSRe-jgTNnVYIq_F0lSlWTkHwasCWqhE" +
                "z-Na3GkUVLFM9w7TIjH2WgyW8Nsa7Y6GF0S8_tZZfisTnZcgqfKPeUPPd451hOlMY_zI3qUZvxYRfbmdmFHt53HZduqr2UtHBy" +
                "bUAONPAC-9DVjgoWqHYlgKX8qR-lPE9qJi_aPWvjuteyzlONMDa3N37Qc1PY2UfL2KfhRtUvsimGoFDl7c23BSPPD3xTSQ8vRA" +
                "tovP28ArfhHrrNR5g-VpMlCHdjsOkpzTpZi4PEc16grx9bBvODLu4qTyClSiB8nBzxpq0SqGwRGJYbmYCUzbvOpVgt2uUzj6LA" +
                "2tFRBFgfn8L3jCRcyel3jKHz9a6WeaOFf4sL0mI");
        Whitebox.invokeMethod(LicenseValidator.class, "inspectExpireDate", jwt);
    }

    @Test(expected = LicenseKeyExpiredException.class)
    public void inspectExpireDate_LicenseKeyExpiredExceptionThrown() throws Exception {
        DecodedJWT jwt = JWT.decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ3c28yIiwicHJvZHVjdENvZGV" +
                "zIjoid3NvMmFtIn0.RlFoz72MIBr13eXEHUSFP3VcT-ud6L41GmIkdypvtKTZV6BGrguAIxUCyH36FkT76pw72An8RzQyCwvKd" +
                "lU2oYz2Rz4j4mdWULkztwnmr2s-sYNshjBrdfJ9qKx5bw3QKk89AR_U1ozb5w13BUNHNyC9-oXCqnq1ZbfyybBVQccOMTM2XLb" +
                "m5EVK3XklaNZFslVBAN1bBhDp48MaTLGC4REG-XNwx_Ki_6n3erteKM_2ejVwFn4bW_LWpo-dXF3zYemuLexKwhvF1Jv1TN_CP" +
                "olWEVwKTZFoB3ljvM3J5_k6cWe5uYaXOusNhGUgry7z7hlZHoHl0IY-25RxHr9sULjPEXJ7I-eZfs8jABYw7ixhq-QS10Qfdnh" +
                "mGaQk5GJ41ptVQ_sQgcMSoBfjcLY6E4iQR9UrttvsWA1l7J0m2HOtZtjKfFjz9klhONLxe0Ek3v0jXe2zEtm4sNVBTQu7dvZ2o" +
                "agc32NSZelmD7O_fu7LJH1Nm4CJh8x1h6c83i3vaovHJtSahWlUbYrGORLcs4yDNDO2LTsQc_Gal-0V3_5uyGPOnyuztLg5A4H" +
                "vd0ZnxV88rYvVUdbam0w2LRFJNAxNQ3xCWjNQzWLLzLbUwvsW3sHgg24yQ76pgU5XOpCRrQV4cjNgOtKmPdYlu7R6G1_xnmtsS" +
                "A1eUwfk9zdyeLw");
        Whitebox.invokeMethod(LicenseValidator.class, "inspectExpireDate", jwt);
    }
}
