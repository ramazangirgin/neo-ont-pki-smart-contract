#if NEO
using System.Numerics;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.ont;
using Neo.SmartContract.Framework.Services.Neo;

namespace CertLedgerBusinessSCTemplate_NeoVM.io.certledger.smartcontract
{
    public class PaymentManager
    {
        //todo: Decide fee amount for Operations and later change
        private const ulong FACTOR = 1;
        private const ulong CERTIFICATE_OPERATION_FEE = 1 * FACTOR;

        public static bool IsAccountBalanceSufficientCertificateOperation(byte[] accountAddress)
        {
            BigInteger accountCertCreditBalance = (BigInteger) retrieveAccountCertCreditBalance(accountAddress);
            return accountCertCreditBalance >= CERTIFICATE_OPERATION_FEE;
        }

        public static bool ChargeFeeForCertificateOperation(byte[] accountAddress)
        {
            return (bool) transferAmountFromAccountAsOperationFee(accountAddress, CERTIFICATE_OPERATION_FEE);
        }

        private static object retrieveAccountCertCreditBalance(byte[] accountAddress)
        {
            object[] arr = new object[1];
            arr[0] = accountAddress;
            Logger.log("Calling Credit Smart Contract -> BalanceOf Operation");
            object ret = CertLedgerBusinessSmartContract.CertCreditMethodCall("BalanceOf", arr);
            Runtime.Notify("Credit Smart Contract -> BalanceOf Operation Return Value ");
            Runtime.Notify(ret);
            return ret;
        }

        private static object transferAmountFromAccountAsOperationFee(byte[] fromAddress, BigInteger amount)
        {
            object[] arr = new object[2];
            arr[0] = fromAddress;
            arr[1] = amount;
            Logger.log("Calling Credit Smart Contract -> Spend Operation");
            object ret = CertLedgerBusinessSmartContract.CertCreditMethodCall("Spend", arr);
            Runtime.Notify("Credit Smart Contract -> Spend Operation Return Value: ");
            Runtime.Notify(ret);
            return ret;
        }
    }
}
#endif