package certledger.common;

public class Notify {

    private String ContractAddress;

    private String[] States;

    public String getContractAddress() {
        return ContractAddress;
    }

    public void setContractAddress(String ContractAddress) {
        this.ContractAddress = ContractAddress;
    }

    public String[] getStates() {
        return States;
    }

    public void setStates(String[] States) {
        this.States = States;
    }

    @Override
    public String toString() {
        return "ClassPojo [ContractAddress = " + ContractAddress + ", States = " + States + "]";
    }
}
