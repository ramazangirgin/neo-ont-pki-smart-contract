package certledger;

import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Address;
import com.github.ontio.smartcontract.neovm.abi.AbiInfo;
import org.assertj.core.util.Lists;

import java.math.BigInteger;
import java.util.ArrayList;

public class CertCreditTransactionManager extends TransactionManager {

    public CertCreditTransactionManager(OntSdk ontSdk, Account account) {
        super(ontSdk, account);
    }

    public Object sendIssueCreditForAccountTransaction(String smartContractAddress, BigInteger amount, AbiInfo abiinfo) throws Exception {
        String name = "Issue";
        ArrayList<Object> byteArrayParamList = Lists.newArrayList(account.serializePublicKey(), amount.longValue());

        return sendObjectRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }

    public Object sendInitializeCreditSC(String smartContractAddress, byte[] certTokenSCAddress, byte[] businessSCAddress, AbiInfo abiinfo) throws Exception {
        String name = "Deploy";
        ArrayList<byte[]> byteArrayParamList = Lists.newArrayList(certTokenSCAddress, businessSCAddress);
        return sendRequest(smartContractAddress, byteArrayParamList, abiinfo, name);
    }
}
