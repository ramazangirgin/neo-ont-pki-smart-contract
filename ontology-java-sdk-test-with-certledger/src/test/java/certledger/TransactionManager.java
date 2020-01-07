package certledger;

import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Helper;
import com.github.ontio.smartcontract.neovm.abi.AbiFunction;
import com.github.ontio.smartcontract.neovm.abi.AbiInfo;
import com.github.ontio.smartcontract.neovm.abi.Parameter;

import java.util.ArrayList;
import java.util.List;

public class TransactionManager {
    protected OntSdk ontSdk;
    protected Account account;

    public TransactionManager(OntSdk ontSdk, Account account) {
        this.ontSdk = ontSdk;
        this.account = account;
    }

    protected Object sendRequest(String smartContractAddress, List<byte[]> byteArrayParamList, AbiInfo abiinfo, String name) throws Exception {
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

    protected Object sendObjectRequest(String smartContractAddress, List<Object> paramArray, AbiInfo abiinfo, String name) throws Exception {
        AbiFunction func = abiinfo.getFunction(name);
        func.setParamsValue(paramArray.toArray());
        return ontSdk.neovm().sendTransaction(Helper.reverse(smartContractAddress), account, account, 2000000, 0, func, false);
    }
}
