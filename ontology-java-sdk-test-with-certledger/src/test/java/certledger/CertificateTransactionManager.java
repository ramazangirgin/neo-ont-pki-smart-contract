package certledger;

import certledger.util.KeyUtil;
import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Helper;
import com.github.ontio.smartcontract.neovm.abi.AbiFunction;
import com.github.ontio.smartcontract.neovm.abi.AbiInfo;
import com.github.ontio.smartcontract.neovm.abi.Parameter;
import org.apache.commons.lang.ArrayUtils;
import org.assertj.core.util.Lists;
import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

import static certledger.BaseCertLedgerTest.certLedgerBoardTestPrivateKeyPath;

public class CertificateTransactionManager {

    private static final byte[] OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE = Hex.decode("4144445f545255535445445f524f4f545f43415f4345525449464943415445");
    private static final byte[] OPERATION_UNTRUST_ROOT_CA_CERTIFICATE = Hex.decode("554e54525553545f524f4f545f43415f4345525449464943415445");
    private static final byte[] OPERATION_REVOKE_SSL_CERTIFICATE = Hex.decode("5245564f4b455f53534c5f4345525449464943415445");
    private static final byte[] OPERATION_ADD_SUBCA_CERTIFICATE = Hex.decode("4144445f53554243415f4345525449464943415445");
    private static final byte[] OPERATION_REVOKE_SUBCA_CERTIFICATE = Hex.decode("5245564f4b455f53554243415f4345525449464943415445");
    private static final byte[] OPERATION_REPORT_FRAUD_CERTIFICATE = Hex.decode("4f5045524154494f4e5f5245504f52545f4652415544");
    private static final byte[] OPERATION_APPROVE_FRAUD_REPORT = Hex.decode("4f5045524154494f4e5f415050524f56455f46524155445f5245504f5254");
    private static final byte[] OPERATION_REJECT_FRAUD_REPORT = Hex.decode("4f5045524154494f4e5f52454a4543545f46524155445f5245504f5254");

    private OntSdk ontSdk;
    private Account account;

    public CertificateTransactionManager(OntSdk ontSdk, Account account) {
        this.ontSdk = ontSdk;
        this.account = account;
    }

    public Object sendTrustRootCertificateRequest(String smartContractAddress, byte[] rootCertificateEncoded, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "AddRootCACertificate";
        return sendRequest(smartContractAddress, rootCertificateEncoded, requestSignature, abiinfo, name);
    }

    public Object sendUnTrustRootCertificateRequest(String smartContractAddress, byte[] rootCertificateEncoded, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "UntrustRootCACertificate";
        return sendRequest(smartContractAddress, rootCertificateEncoded, requestSignature, abiinfo, name);
    }

    public Object sendAddSubCaCertificateRequest(String smartContractAddress, byte[] certificateEncoded, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "AddSubCACertificate";
        return sendRequest(smartContractAddress, certificateEncoded, requestSignature, abiinfo, name);
    }

    public Object sendRevokeSubCACertificateRequest(String smartContractAddress, byte[] certificateEncoded, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "RevokeSubCACertificate";
        return sendRequest(smartContractAddress, certificateEncoded, requestSignature, abiinfo, name);
    }

    public Object sendAddSSLCertificateRequest(String smartContractAddress, byte[] certificateEncoded, AbiInfo abiinfo) throws Exception {
        String name = "AddSSLCertificate";
        return sendRequest(smartContractAddress, Lists.newArrayList(account.serializePublicKey(), certificateEncoded), abiinfo, name);
    }

    public Object sendRevokeSSLCertificateRequest(String smartContractAddress, byte[] certificateEncoded, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "RevokeSSLCertificate";
        return sendRequest(smartContractAddress, certificateEncoded, requestSignature, abiinfo, name);
    }

    public Object sendReportFraudRequest(String smartContractAddress, byte[] fraudId, byte[] fakeButValidCertificate, byte[] signerCertificate, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "ReportFraud";
        ArrayList<byte[]> byteArrayParamList = Lists.newArrayList(fraudId, fakeButValidCertificate, signerCertificate, requestSignature);
        return sendRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }

    public Object sendApproveFraudReportRequest(String smartContractAddress, byte[] fraudId, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "ApproveFraudReport";
        ArrayList<byte[]> byteArrayParamList = Lists.newArrayList(fraudId, requestSignature);
        return sendRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }

    public Object sendRejectFraudReportRequest(String smartContractAddress, byte[] fraudId, byte[] requestSignature, AbiInfo abiinfo) throws Exception {
        String name = "RejectFraudReport";
        ArrayList<byte[]> byteArrayParamList = Lists.newArrayList(fraudId, requestSignature);
        return sendRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }

    public Object sendResetStorageRequest(String smartContractAddress, AbiInfo abiinfo) throws Exception {
        String name = "ResetStorage";
        return sendRequest(smartContractAddress, "00".getBytes(), abiinfo, name);
    }

    public Object sendDestroySmartContractRequest(String smartContractAddress, AbiInfo abiinfo) throws Exception {
        String name = "Destroy";
        return sendRequest(smartContractAddress, Lists.newArrayList(), abiinfo, name);
    }

    public Object sendParseCertificateRequest(String smartContractAddress, byte[] rootCertificateEncoded, AbiInfo abiinfo) throws Exception {
        String name = "ParseCertificate";
        return sendRequest(smartContractAddress, rootCertificateEncoded, abiinfo, name);
    }

    public Object sendLogCACertificateStorageStatusRequest(String smartContractAddress, byte[] rootCertificateEncoded, AbiInfo abiinfo) throws Exception {
        String name = "LogCACertificateStorageStatus";
        return sendRequest(smartContractAddress, rootCertificateEncoded, abiinfo, name);
    }

    public Object sendLogSSLCertificateStorageStatusRequest(String smartContractAddress, byte[] rootCertificateEncoded, AbiInfo abiinfo) throws Exception {
        String name = "LogSSLCertificateStorageStatus";
        return sendRequest(smartContractAddress, rootCertificateEncoded, abiinfo, name);
    }

    public Object sendLogFraudReportStatusRequest(String smartContractAddress, byte[] fraudId, AbiInfo abiinfo) throws Exception {
        String name = "LogFraudReportStatus";
        return sendRequest(smartContractAddress, fraudId, abiinfo, name);
    }

    public Object sendLogDomainCertificatesRequest(String smartContractAddress, String domainName, AbiInfo abiinfo) throws Exception {
        String name = "LogDomainCertificates";
        return sendRequest(smartContractAddress, domainName.getBytes(), abiinfo, name);
    }

    public Object sendVerifyCertificateSignatureRequest(String smartContractAddress, byte[] certificateEncoded, byte[] issuerCertificateEncoded, AbiInfo abiinfo) throws Exception {
        String name = "VerifyCertificateSignature";
        return sendRequest(smartContractAddress, Lists.newArrayList(certificateEncoded, issuerCertificateEncoded), abiinfo, name);
    }

    public Object sendRequest(String smartContractAddress, byte[] certificateEncoded, AbiInfo abiinfo, String name) throws Exception {
        return sendRequest(smartContractAddress, Lists.newArrayList(certificateEncoded), abiinfo, name);
    }

    public Object sendRequest(String smartContractAddress, byte[] certificateEncoded, byte[] requestSignature, AbiInfo abiinfo, String name) throws Exception {
        ArrayList<byte[]> byteArrayParamList = Lists.newArrayList(certificateEncoded, requestSignature);
        return sendRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }


    private Object sendRequest(String smartContractAddress, List<byte[]> byteArrayParamList, AbiInfo abiinfo, String name) throws Exception {
        AbiFunction func = abiinfo.getFunction(name);
        List<Parameter> parameters = new ArrayList<>();
        for (byte[] paramValue : byteArrayParamList) {
            Parameter certParam = new Parameter();
            certParam.type = "ByteArray";
            certParam.setValue(paramValue);
            parameters.add(certParam);
        }
        func.parameters = parameters;
        return ontSdk.neovm().sendTransaction(Helper.reverse(smartContractAddress), account, account, 2000000, 0, func, false);
    }

    public byte[] generateAddTrustedRootCACertificateRequestSignature(byte[] rootCertValue) {
        byte[] operation = OPERATION_ADD_TRUSTED_ROOT_CA_CERTIFICATE;
        byte[] dataForSign = ArrayUtils.addAll(operation, rootCertValue);
        return generateCertLedgerBoardRequestSignature(dataForSign);
    }

    public byte[] generateRevokeSSLCertificateECDSARequestSignature(byte[] sslCertValue, String privateKeyPemFilePath) {
        try {
            PrivateKey privateKey = KeyUtil.loadECPrivateKeyFromPemFile(privateKeyPemFilePath);
            Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
            signature.initSign(privateKey);
            byte[] dataForSign = ArrayUtils.addAll(OPERATION_REVOKE_SSL_CERTIFICATE, sslCertValue);
            signature.update(dataForSign);
            return signature.sign();
        } catch (Exception exc) {
            throw new RuntimeException("Signature Generation Exception", exc);
        }
    }

    public byte[] generateRevokeSSLCertificateRSAPSSRequestSignature(byte[] sslCertValue, String privateKeyPemFilePath) {
        byte[] operation = OPERATION_REVOKE_SSL_CERTIFICATE;
        return generateRSAPssRequest(sslCertValue, privateKeyPemFilePath, operation);
    }

    public byte[] generateReportFraudRequestSignatureWithRSAPSS(byte[] sslCertValue, String privateKeyPemFilePath) {
        byte[] operation = OPERATION_REPORT_FRAUD_CERTIFICATE;
        return generateRSAPssRequest(sslCertValue, privateKeyPemFilePath, operation);
    }

    public byte[] generateApproveFraudReportRequestSignature(byte[] fraudId) {
        byte[] operation = OPERATION_APPROVE_FRAUD_REPORT;
        byte[] dataForSign = ArrayUtils.addAll(operation, fraudId);
        byte[] signature = generateCertLedgerBoardRequestSignature(dataForSign);
        return signature;
    }

    public byte[] generateRejectFraudReportRequestSignature(byte[] fraudId) {
        byte[] operation = OPERATION_REJECT_FRAUD_REPORT;
        byte[] dataForSign = ArrayUtils.addAll(operation, fraudId);
        byte[] signature = generateCertLedgerBoardRequestSignature(dataForSign);
        return signature;
    }

    private byte[] generateCertLedgerBoardRequestSignature(byte[] dataForSign) {
        try {
            PrivateKey privateKey = KeyUtil.loadPrivateKey(certLedgerBoardTestPrivateKeyPath);
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(dataForSign);
            return ecdsaSign.sign();
        } catch (Exception exc) {
            throw new RuntimeException("Signature Generation Exception", exc);
        }
    }

    public byte[] generateAddSubCARSAPSSRequestSignature(byte[] certValue, String privateKeyPemFilePath) {
        byte[] operation = OPERATION_ADD_SUBCA_CERTIFICATE;
        return generateRSAPssRequest(certValue, privateKeyPemFilePath, operation);
    }

    public byte[] generateRevokeSubCACertificateRSAPSSRequestSignature(byte[] sslCertValue, String privateKeyPemFilePath) {
        byte[] operation = OPERATION_REVOKE_SUBCA_CERTIFICATE;
        return generateRSAPssRequest(sslCertValue, privateKeyPemFilePath, operation);
    }

    private byte[] generateRSAPssRequest(byte[] sslCertValue, String privateKeyPemFilePath, byte[] operation) {
        try {
            PrivateKey privateKey = KeyUtil.loadRSAPrivateKeyFromPemFile(privateKeyPemFilePath);
            Signature signature = Signature.getInstance("SHA256withRSA/PSS", "BC");
            signature.initSign(privateKey);
            byte[] dataForSign = ArrayUtils.addAll(operation, sslCertValue);
            signature.update(dataForSign);
            return signature.sign();
        } catch (Exception exc) {
            throw new RuntimeException("Signature Generation Exception", exc);
        }
    }

    private byte[] generateRevokeSSLCertificateRequestSignature(String algorithmName, byte[] sslCertValue, String privateKeyPemFilePath) {
        try {
            PrivateKey privateKey = KeyUtil.loadRSAPrivateKeyFromPemFile(privateKeyPemFilePath);
            Signature signature = Signature.getInstance(algorithmName, "BC");
            signature.initSign(privateKey);
            byte[] dataForSign = ArrayUtils.addAll(OPERATION_REVOKE_SSL_CERTIFICATE, sslCertValue);
            signature.update(dataForSign);
            return signature.sign();
        } catch (Exception exc) {
            throw new RuntimeException("Signature Generation Exception", exc);
        }
    }

    public byte[] generateUntrustRootCACertificateRequestSignature(byte[] rootCertValue) {
        try {
            PrivateKey privateKey = KeyUtil.loadPrivateKey(certLedgerBoardTestPrivateKeyPath);
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            byte[] dataForSign = ArrayUtils.addAll(OPERATION_UNTRUST_ROOT_CA_CERTIFICATE, rootCertValue);
            ecdsaSign.update(dataForSign);
            return ecdsaSign.sign();
        } catch (Exception exc) {
            throw new RuntimeException("Signature Generation Exception", exc);
        }
    }
}
