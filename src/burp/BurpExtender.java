package burp;

import b4dpxl.timestamp.TimestampEditor;

public class BurpExtender implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        new TimestampEditor(callbacks);

    }

}
