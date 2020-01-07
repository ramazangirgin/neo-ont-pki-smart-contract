package certledger;

import certledger.common.Event;
import certledger.common.Notify;
import certledger.common.TransactionData;
import com.alibaba.fastjson.JSON;
import com.github.ontio.OntSdk;
import com.github.ontio.account.Account;
import com.github.ontio.common.Address;
import com.github.ontio.core.transaction.Transaction;
import com.github.ontio.network.exception.ConnectorException;
import com.github.ontio.sdk.manager.ConnectMgr;
import com.github.ontio.smartcontract.neovm.abi.AbiInfo;
import com.google.gson.Gson;
import org.assertj.core.util.Lists;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.awaitility.Awaitility.with;

public class BaseCertLedgerTest {

    private final static String walletFile = "cert-ledger-data/wallet.dat";

    private final static String businessSmartContractAvmFile = "cert-ledger-data/CertLedgerBusinessSCTemplate_NeoVM.avm";
    private final static String businessSmartContractAbiFile = "cert-ledger-data/CertLedgerBusinessSCTemplate_NeoVM.abi.json";
    protected String businessSmartContractAbiContent;
    protected String businessSmartContractAddress;
    protected AbiInfo businessSmartContractAbiinfo;
    protected CertificateTransactionManager certificateTransactionManager;

    private final static String creditSmartContractAvmFile = "cert-ledger-data/certledger-credit-smartcontract-hex.avm";
    private final static String creditSmartContractAbiFile = "cert-ledger-data/certledger-credit-smartcontract.abi.json";
    protected String creditSmartContractAddress;
    protected AbiInfo creditSmartContractAbiInto;
    protected CertCreditTransactionManager certCreditTransactionManager;
    protected final static String certLedgerBoardTestPrivateKeyPath = "cert-ledger-data/cert-ledger-board-test-private-key.dat";

    private final static String accountAddress = "AQ892hu1AnyRcZPpEhEu8AprSqMVxxfEtk";
    private final static String accountPassword = "19832329";

    private OntSdk ontSdk;
    private Account account;

    @Before
    public void setUp() throws Exception {
        String ip = "http://127.0.0.1";
        // String ip = "http://192.168.160.128";
        String rpcUrl = ip + ":" + "20336";
        String restUrl = ip + ":" + "20334";
        ontSdk = OntSdk.getInstance();
        ontSdk.setRpc(rpcUrl);
        ontSdk.setRestful(restUrl);
        ontSdk.setDefaultConnect(ontSdk.getRpc());
        ontSdk.openWalletFile(walletFile);
        account = ontSdk.getWalletMgr().getAccount(accountAddress, accountPassword);

        byte[] avmContentBytes = Files.readAllBytes(Paths.get(businessSmartContractAvmFile));
        String smartContractCodeHex = Hex.toHexString(avmContentBytes);
        businessSmartContractAbiContent = Files.readAllLines(Paths.get(businessSmartContractAbiFile)).stream()
                .collect(Collectors.joining());
        businessSmartContractAddress = Address.AddressFromVmCode(smartContractCodeHex).toHexString();
        boolean allreadyDeployed = false;
        try {
            ontSdk.getConnect().getContract(businessSmartContractAddress);
            allreadyDeployed = true;
        } catch (Exception exc) {

        }
        if (!allreadyDeployed) {
            deploySmartContract(smartContractCodeHex, businessSmartContractAddress, 100000000, 15000);
        }

        byte[] creditSmartContractAvmHexBytes = Files.readAllBytes(Paths.get(creditSmartContractAvmFile));
        byte[] creditSmartContractContent = Hex.decode(new String(creditSmartContractAvmHexBytes));
        String creditSmartContractCodeHex = Hex.toHexString(creditSmartContractContent);
        String creditSmartContractAbiFileContent = Files.readAllLines(Paths.get(creditSmartContractAbiFile)).stream()
                .collect(Collectors.joining());
        creditSmartContractAbiInto = JSON.parseObject(creditSmartContractAbiFileContent, AbiInfo.class);
        creditSmartContractAddress = Address.AddressFromVmCode(creditSmartContractCodeHex).toHexString();

        boolean creditSmartContractAlreadyDeployed = false;
        try {
            ontSdk.getConnect().getContract(creditSmartContractAddress);
            creditSmartContractAlreadyDeployed = true;
        } catch (Exception exc) {

        }

        if (!creditSmartContractAlreadyDeployed) {
            System.out.println("Deploying Credit Smart Contract");
            System.out.println("--------------------------------");
            deploySmartContract(creditSmartContractCodeHex, creditSmartContractAddress, 100000000, 15000);
            System.out.println("--------------------------------");

            creditSmartContractAbiInto = JSON.parseObject(creditSmartContractAbiFileContent, AbiInfo.class);
            certCreditTransactionManager = new CertCreditTransactionManager(ontSdk, account);
            initializeCertCreditSmartContract("bf106fc479439bd90f58b7d3a805b1b5dcbd92ba".getBytes(), businessSmartContractAddress.getBytes());
            loadCertCreditForAccount();
        }

        businessSmartContractAbiinfo = JSON.parseObject(businessSmartContractAbiContent, AbiInfo.class);
        certificateTransactionManager = new CertificateTransactionManager(ontSdk, account);
        resetSmartContractStorage(businessSmartContractAddress, businessSmartContractAbiinfo);
    }

    private void loadCertCreditForAccount() throws Exception {
        Object response = certCreditTransactionManager.sendIssueCreditForAccountTransaction(creditSmartContractAddress, new BigInteger("10000"), creditSmartContractAbiInto);
        String transactionHex = response.toString();
        System.out.println("Loading Test Cert Credit For Account");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
    }

    private void initializeCertCreditSmartContract(byte[] certTokenSCAddress, byte[] businessSCAddress) throws Exception {
        Object response = certCreditTransactionManager.sendInitializeCreditSC(creditSmartContractAddress, certTokenSCAddress, businessSCAddress, creditSmartContractAbiInto);
        String transactionHex = response.toString();
        System.out.println("Initializing Credit Token Smart Contract With Business & Cert Token Smart Contract Addresses");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
    }

    private void resetSmartContractStorage(String smartContractAddress, AbiInfo abiinfo) throws Exception {
        Object response = certificateTransactionManager.sendResetStorageRequest(smartContractAddress, abiinfo);
        String transactionHex = response.toString();
        System.out.println("Resetting Smart Contract Storage");
        System.out.println("--------------------------------");
        logEvents(transactionHex);
        System.out.println("--------------------------------");
    }

    private void deploySmartContract(String smartContractCodeHex, String smartContractAddress, int i, int i2) throws Exception {
        Transaction tx = ontSdk.vm().makeDeployCodeTransaction(smartContractCodeHex, true, "name",
                "v1.0", "author", "email", "desp", account.getAddressU160().toBase58(), i, 0);
        ontSdk.signTx(tx, new Account[][]{{account}});
        ConnectMgr ontSdkConnect = ontSdk.getConnect();
        Object result = ontSdkConnect.sendRawTransaction(tx.toHexString());
        System.out.println("Transaction Result");
        System.out.println("--------------------------------");
        System.out.println(new Gson().toJson(result));
        System.out.println("--------------------------------");

        Thread.sleep(i2);
        Object obj = ontSdk.getConnect().getContract(smartContractAddress);
        System.out.println("Smart Contract Object");
        System.out.println("--------------------------------");
        System.out.println(new Gson().toJson(obj));
        System.out.println("--------------------------------");
    }

    protected void logEvents(String transactionHex) throws ConnectorException, IOException {
        retrieveEvents(transactionHex)
                .forEach(System.out::println);
    }

    protected List<Event> retrieveEvents(String transactionHex) throws ConnectorException, IOException {
        final Object[] smartCodeEvent = {null};
        with().pollDelay(1, SECONDS).and().pollInterval(1, SECONDS)
                .await().atMost(60, SECONDS).until(() -> {
            smartCodeEvent[0] = ontSdk.getConnect().getSmartCodeEvent(transactionHex);
            return smartCodeEvent[0] != null;
        });

        if (smartCodeEvent[0] == null)
            return Lists.newArrayList();
        TransactionData transactionData = new Gson().fromJson(smartCodeEvent[0].toString(), TransactionData.class);
        return Stream.of(transactionData.getNotify())
                .map(Notify::getStates)
                .flatMap(strings -> Arrays.stream(strings).map(this::retrieveEvent))
                .collect(Collectors.toList());
    }

    private Event retrieveEvent(String state) {
        Event event = new Event();
        event.setHexValue(state);
        if (!state.startsWith("30")) {
            try {
                event.setStringValue(new String(Hex.decode(state)));
            } catch (Exception exc) {
            }
        }
        return event;
    }
}