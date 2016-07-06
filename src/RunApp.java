import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.RequestAcceptEncoding;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.AllowAllHostnameVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.util.EntityUtils;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;


//USEAGE:
//TO BUILD JAR file:
// 1. In IntelliJ Select Build -> Build Artifacts

/*TO RUN JAR file:
    1. Open command line and cd to the artifact location
    2. To run against local environment type:
            java -Djavax.net.debug="ssl:handshake" -jar SecureSocketLayerTester.jar /Users/evgheni/SSLKeys/ keyStore.jks P@ssw0rd trustStore.jks P@ssw0rd test_user@myserver.com P@ssw0rd false https localhost 8443 /MyApp/api/connect/endpoint

   3. To run against specific environment with predefined properties file type:
            java -Djavax.net.debug="ssl:handshake" -jar SecureSocketLayerTester.jar
*/
public class RunApp {

    //args[0]
    private static String sslKeysLocation; //                      Can be provided via:  args[0].  Default value: '/Users/evgheni/SSLKeys/'.

    private static String keyStoreName; //                         Can be provided via:  args[1].  Default value: 'keyStore.jks'.
    private static char[] keyStorePassword; //                     Can be provided via:  args[2].  Default value: 'P@ssw0rd'.
    private static KeyStore keyStore; //stores data loaded from keyStore specified above

    private static String trustStoreName; //                       Can be provided via:  args[3]. Default value: 'trustStore.jks'
    private static char[] trustStorePassword; //                   Can be provided via:  args[4]. Default value: 'P@ssw0rd'
    private static KeyStore trustStore; //stores data loaded from trustStore specified above


    private static String integrationUserName; //                   Can be provided via:  args[5]. Default value: 'test_user@myserver.com'
    private static String integrationUserPassword; //               Can be provided via:  args[6]. Default value: 'P@ssw0rd'

    private static boolean ignoreSSLErrors; //                      Can be provided via:  args[7]. Default value: 'false'


    private static String socketProtocol;//                         Can be provided via:  args[8]. Default value: 'https'
    private static String serverName;//                             Can be provided via:  args[9]. Default value: 'localhost'
    private static int portNumber; //                               Can be provided via:  args[10]. Default value: '443'
    private static String applicationPath;//                        Can be provided via:  args[11]. Default value: '/MyApp/api/connect/endpoint'


    private static void initEnvironment(String[] args){


        if(args.length==11){
            System.err.println("Loading data from supplied parameters");
            //location of the stores:
            sslKeysLocation = args[0].length()>0?args[0]:"/Users/evgheni/SSLKeys/";
            //key store name and password for SSL context:
            keyStoreName = args[1].length() >0 ? args[1] : "keyStore.jks";
            keyStorePassword = args[2].length()>0 ? args[2].toCharArray() : "P@ssw0rd".toCharArray();
            //trust store name and password for SSL context:
            trustStoreName = args[3].length()>0 ? args[3] : "trustStore.jks";
            trustStorePassword = args[4].length()>0 ? args[4].toCharArray() : "P@ssw0rd".toCharArray();
            integrationUserName = args[5].length()>0 ? args[5] : "test_user@myserver.com";
            integrationUserPassword = args[6].length()>0 ? args[6] : "P@ssw0rd";
            ignoreSSLErrors = Boolean.parseBoolean(args[7]);
            socketProtocol = args[8].length()>0 ? args[8] : "https";
            serverName = args[9].length()>0 ? args[9] : "localhost";
            portNumber = args[10].length()>0 ? Integer.parseInt(args[10]) : 443;
            applicationPath=args[11].length()>0 ? args[11] : "/MyApp/api/connect/endpoint";
        }
        //load data from properties file:
        else {
            System.err.println("Loading data from properties file ...");

            Properties properties = new Properties();
            InputStream inputStream=null;

            try {
                inputStream = RunApp.class.getClassLoader().getResourceAsStream("testerConfig.properties");
                properties.load(inputStream);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }

            sslKeysLocation = properties.getProperty("sslKeysLocation");
            keyStoreName = properties.getProperty("keyStoreName");
            keyStorePassword = properties.getProperty("keyStorePassword").toCharArray();
            trustStoreName = properties.getProperty("trustStoreName");
            trustStorePassword = properties.getProperty("trustStorePassword").toCharArray();
            integrationUserName = properties.getProperty("intergationUserName");
            integrationUserPassword = properties.getProperty("intergationUserPassword");
            ignoreSSLErrors = Boolean.parseBoolean(properties.getProperty("ignoreSSLErrors"));
            socketProtocol = properties.getProperty("socketProtocol");
            serverName = properties.getProperty("serverName");
            portNumber = Integer.parseInt(properties.getProperty("portNumber"));
            applicationPath=properties.getProperty("applicationPath");
        }


        try{
            keyStore = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e){
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        try{
            trustStore = KeyStore.getInstance("JKS");
        }
        catch (KeyStoreException e){
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //Try to load data from registered private key store into memory which can be used by our client to authenticate itself against server
        File keyStoreLocation = new File(sslKeysLocation+keyStoreName);
        try{
            keyStore.load(new FileInputStream(keyStoreLocation), keyStorePassword);
        } catch (CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        //Try to load data from registered trust store into memory which will be used by our client to authenticate server
        File trustStoreLocation = new File(sslKeysLocation+trustStoreName);
        try{
            trustStore.load(new FileInputStream(trustStoreLocation), trustStorePassword);
        } catch (CertificateException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static void printIntitParams() {
        System.out.println("***********************************");
        System.out.println("Completed params initialization as:");
        System.out.println("***********************************");
        System.out.println("sslKeysLocation: "+sslKeysLocation);
        System.out.println("keyStoreName: "+keyStoreName);
        System.out.println("keyStorePassword: "+keyStorePassword);
        System.out.println("trustStoreName: "+trustStoreName);
        System.out.println("trustStorePassword: "+trustStorePassword);
        System.out.println("integrationUserName: "+ integrationUserName);
        System.out.println("integrationUserPassword: "+ integrationUserPassword);
        System.out.println("ignoreSSLErrors: "+ignoreSSLErrors);
        System.out.println("socketProtocol: "+socketProtocol);
        System.out.println("serverName: "+serverName);
        System.out.println("portNumber: "+ portNumber);
        System.out.println("applicationPath: "+applicationPath);
        System.out.println("***********************************");
        System.out.println("System params set to:");
        System.out.println("***********************************");
        System.out.println("-Djavax.net.debug :"+System.getProperty("javax.net.debug"));
        System.out.println("***********************************");
    }

    public static void main(String[] args) {
        initEnvironment(args);
        printIntitParams();

        HttpHost target;
        HttpGet  httpGet;
        HttpResponse response;
        HttpEntity entity;

        try{

            //Init new http client
            DefaultHttpClient httpClient = newClient();

            //Setup target:
            target = new HttpHost(serverName, portNumber, socketProtocol);
            //Setup application path:
            httpGet = new HttpGet(applicationPath);
            //Issue request:
            response = httpClient.execute(target, httpGet);
            entity = response.getEntity();

            System.err.println("***************RECEIVED RESPONSE FROM SERVER**********************");
            System.err.println("Response Status:"  + response.getStatusLine());
            System.err.println("******************************************************************");
            System.err.println("Response Content:" + EntityUtils.toString(entity));
            System.err.println("******************************************************************");

            EntityUtils.consume(entity);
        }
        catch (Exception e){
            throw new RuntimeException(e);
        }
    }


    private static DefaultHttpClient newClient() {
        //Create new client with connection socket on port 8443:
        DefaultHttpClient client = generateClient(socketProtocol, portNumber);

        //Add auth header credentials:
        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(integrationUserName, integrationUserPassword));
        client.setCredentialsProvider(credentialsProvider);

        //Add request/response interceptors:
        client.addRequestInterceptor(new RequestAcceptEncoding());
        client.addResponseInterceptor(new ResponseContentEncoding());

        return client;
    }

    private static DefaultHttpClient generateClient(String protocol, int port){
        //Setup connection socket:
        SSLSocketFactory socketFactory = generateSocketFactory();

        Scheme scheme = new Scheme(protocol, port, socketFactory);
        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(scheme);
        ClientConnectionManager connectionManager = new SingleClientConnManager(schemeRegistry);


        /**
         * Create new HTTP client from parameters and connection manager.
         *
         * @param params    the parameters
         * @param connectionManager    the connection manager
         *
         * This class sets up the following parameters if not explicitly set:
         * Version: HttpVersion.HTTP_1_1
         * ContentCharset: HTTP.DEFAULT_CONTENT_CHARSET
         * NoTcpDelay: true
         * SocketBufferSize: 8192
         * UserAgent: Apache-HttpClient/release (java 1.5)
         */
        return new DefaultHttpClient(connectionManager);
    }


    /*
    *  Layered socket factory for TLS/SSL connections.
    *  SSLSocketFactory can be used to validate the identity of the HTTPS server against a list of trusted certificates and to authenticate to the HTTPS server using a private key.
    *
    * !  SSLSocketFactory ENABLE SERVER AUTHENTICATION when supplied with a trust-store file containing one or several trusted certificates.
    *    The client secure socket will reject the connection during the SSL session handshake if the target HTTPS server attempts to authenticate itself with a non-trusted certificate.
    *
    *       Use JDK keytool utility to import a trusted certificate and generate a trust-store file:
    *
    *           keytool -import -alias "my server cert" -file server.crt -keystore my.truststore
    *
    *  In special cases the standard trust verification process can be bypassed by using a custom TrustStrategy. This interface is primarily intended for allowing self-signed certificates to be accepted as trusted without having to add them to the trust-store file.
    *
    * ! SSLSocketFactory will ENABLE CLIENT AUTHENTICATION when supplied with a key-store file containing a private key/public certificate pair.
    *   The client secure socket will use the private key to authenticate itself to the target HTTPS server during the SSL session handshake if requested to do so by the server.
    *   The target HTTPS server will in its turn verify the certificate presented by the client in order to establish client's authenticity.
    *
    *       Use the following sequence of actions to generate a key-store file:
    *
    *          Use JDK keytool utility to generate a new key
    *
    *               keytool -genkey -v -alias "my client key" -validity 365 -keystore my.keystore
    *
    *           For simplicity use the same password for the key as that of the key-store
    *
    *
    *           Issue a certificate signing request (CSR)
    *
    *               keytool -certreq -alias "my client key" -file mycertreq.csr -keystore my.keystore
    *
    *
    *           Send the certificate request to the trusted Certificate Authority for signature. One may choose to act as her own CA and sign the certificate request using a PKI tool, such as OpenSSL.
    *
    *
    *           Import the trusted CA root certificate
    *
    *                keytool -import -alias "my trusted ca" -file caroot.crt -keystore my.keystore
    *
    *
    *           Import the PKCS#7 file containing the complete certificate chain
    *
    *               keytool -import -alias "my client key" -file mycert.p7 -keystore my.keystore
    *
    *
    *            Verify the content the resultant keystore file
    *
    *               keytool -list -v -keystore my.keystore
    */
    private static SSLSocketFactory generateSocketFactory(){
        SSLSocketFactory socketFactory;
        //setup SSL socket which will ignore SSL errors:
        try{
            if(ignoreSSLErrors) {
                System.err.println("Requested SSL socket connection that will ignore SSL certificate errors.  This makes a man-in-the-middle attack possible and should only be used for testing.");

                TrustStrategy trustAllStrategy = new TrustStrategy() {
                    public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        System.err.println("***************************************************");
                        System.err.println("Authentication type set as: " + authType);
                        System.err.println("***************************************************");
                        System.err.println(" Printing X509 certificate chain");
                        System.err.println("***************************************************");
                        for (X509Certificate cert : chain) {
                            System.err.println(cert);
                        }
                        System.err.println("***************************************************");
                        return true;
                    }
                };
                socketFactory = new SSLSocketFactory(trustAllStrategy, new AllowAllHostnameVerifier());
            }
            else {
                System.err.println("Requested SSL Socket connection with disabled client authentication");
                //HERE:           (String algorithm, KeyStore keystore, String keyPassword, KeyStore truststore, SecureRandom random, TrustStrategy trustStrategy, X509HostnameVerifier hostnameVerifier)
                socketFactory = new SSLSocketFactory(trustStore);
            }

            return socketFactory;

        }catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
