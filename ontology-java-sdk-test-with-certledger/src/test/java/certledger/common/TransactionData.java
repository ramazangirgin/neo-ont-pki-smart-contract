package certledger.common;

public class TransactionData {

    private String TxHash;

    private String State;

    private String GasConsumed;

    private Notify[] Notify;

    public String getTxHash() {
        return TxHash;
    }

    public void setTxHash(String TxHash) {
        this.TxHash = TxHash;
    }

    public String getState() {
        return State;
    }

    public void setState(String State) {
        this.State = State;
    }

    public String getGasConsumed() {
        return GasConsumed;
    }

    public void setGasConsumed(String GasConsumed) {
        this.GasConsumed = GasConsumed;
    }

    public Notify[] getNotify() {
        return Notify;
    }

    public void setNotify(Notify[] Notify) {
        this.Notify = Notify;
    }

    @Override
    public String toString() {
        return "ClassPojo [TxHash = " + TxHash + ", State = " + State + ", GasConsumed = " + GasConsumed + ", Notify = " + Notify + "]";
    }
}
