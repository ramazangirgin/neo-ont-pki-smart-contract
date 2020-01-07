package certledger.common;

import java.math.BigInteger;

public class Event {

    private String stringValue;
    private String hexValue;

    public String getStringValue() {
        return stringValue;
    }

    public void setStringValue(String stringValue) {
        this.stringValue = stringValue;
    }


    public String getHexValue() {
        return hexValue;
    }

    public void setHexValue(String hexValue) {
        this.hexValue = hexValue;
    }

    @Override
    public String toString() {
        return "******************* Event ********************\n"+
               "Hex : ["+hexValue+"]\n"+
                "String: ["+stringValue+"]\n"+
                "***********************************************\n";
    }
}
