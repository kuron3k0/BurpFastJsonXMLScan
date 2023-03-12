package burp.DnsLogModule.ExtensionMethod;

import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.YamlReader;
import burp.DnsLogModule.ExtensionInterface.DnsLogAbstract;
import burp.IBurpExtenderCallbacks;
import com.github.kevinsawicki.http.HttpRequest;

import java.io.PrintWriter;

public class PrivateDnslog extends DnsLogAbstract {

    private IBurpExtenderCallbacks callbacks;

    private String dnslogDomainName;

    private YamlReader yamlReader;

    private String checkUrl;

    private String hashStr;

    private String rand;

    public PrivateDnslog(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.rand = CustomHelpers.randomStr(8);
        this.setExtensionName("PrivateDnslog");
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.dnslogDomainName = this.yamlReader.getString("dnsLogModule.privateDomainName");
        this.hashStr = this.yamlReader.getString("dnsLogModule.privateHashStr");
        this.checkUrl = this.yamlReader.getString("dnsLogModule.checkUrl");

        this.setTemporaryDomainName(this.rand+"."+this.hashStr+"."+this.dnslogDomainName);
    }


    @Override
    public String getBodyContent() {
        String url = String.format("%s/api/dns/%s/%s/", this.checkUrl, this.hashStr, this.rand);
        String userAgent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36";

        HttpRequest request = HttpRequest.get(url);
        request.trustAllCerts();
        request.trustAllHosts();
        request.followRedirects(false);
        request.header("User-Agent", userAgent);
        request.header("Accept", "*/*");
        request.readTimeout(30 * 1000);
        request.connectTimeout(30 * 1000);

        String result = request.body();
        if(result.equals("False"))
            return null;
        else if(result.equals("True"))
            return result;

        return null;
    }

    @Override
    public String export() {
        return null;
    }

    @Override
    public void consoleExport() {


    }
}
