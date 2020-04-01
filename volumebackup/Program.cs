
// Version 1.0.1
namespace Oracle.Oci
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;
    using Newtonsoft.Json;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Security;
    using System.Text.Json;
    using Newtonsoft.Json.Linq;

    public class Signing
    {
        public static void Main(string[] args)
        {
            var tenancyId = "ocid1.tenancy.oc1..aaaaaaaa33zmzods56kapqxipjath2cq5naumm23vvevui7jpznyxkjctmya";
            var compartmentId = "ocid1.compartment.oc1..aaaaaaaa4nuufjh2u2wsevzxizto3odfsoxpzrekxib466h6z5zij37xvgwq";
            var userId = "ocid1.user.oc1..aaaaaaaaqfsq7l4htnwbl4zaoqymrpzx2qfmbvqezakxgjnlm5egb4lm7cfa";
            var fingerprint = "d4:00:9c:89:cf:37:1f:0c:08:f8:d3:18:5e:f6:db:91";
            var privateKeyPath = @"C:\oci\keys\oci_api_key.pem";
            var privateKeyPassphrase = "acapulco";
            var torontoAD = "dKyb:CA-TORONTO-1-AD-1";
            var dest = "ca-montreal-1";
            var signer = new RequestSigner(tenancyId, userId, fingerprint, privateKeyPath, privateKeyPassphrase);

            // GET list of block volumes
            var uri = new Uri($"https://iaas.ca-toronto-1.oraclecloud.com/20160918/bootVolumes?availabilityDomain={torontoAD}&compartmentId={compartmentId}");

            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Method = "GET";
            request.Accept = "application/json";
            request.ContentType = "application/json";

            signer.SignRequest(request);
            Console.WriteLine($"Authorization header: {request.Headers["authorization"]}");
                        
            string volumes = ExecuteRequest(request);

            var result = JsonConvert.DeserializeObject<IEnumerable<RootObject>>(volumes);

            var volumesIds = new List<string>();

            foreach (var volume in result)
            {
                volumesIds.Add(volume.id);
            }

            foreach(var id in volumesIds)
            {
                uri = new Uri($"https://iaas.ca-toronto-1.oraclecloud.com/20160918/bootVolumeBackups?compartmentId={compartmentId}&bootVolumeId={id}");
                request = (HttpWebRequest)WebRequest.Create(uri);
                request.Method = "GET";
                request.Accept = "application/json";
                request.ContentType = "application/json";

                signer.SignRequest(request); 

                string serializedObject = ExecuteRequest(request); 

                var backups = JsonConvert.DeserializeObject<IEnumerable<BackupVolume>>(serializedObject); 
          
                foreach(var bkp in backups)
                {                   
                    uri = new Uri($"https://iaas.ca-toronto-1.oraclecloud.com/20160918/bootVolumeBackups/{bkp.id}/actions/copy" );
                   
                    var body = @"{{""destinationRegion"" : ""ca-montreal-1""}}";
                    var bytes = Encoding.UTF8.GetBytes(body);

                    request = (HttpWebRequest)WebRequest.Create(uri);
                    request.Method = "POST";
                    request.Accept = "application/json";
                    request.ContentType = "application/json";          
                    
                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(bytes, 0, bytes.Length);
                    }

                    signer.SignRequest(request);

                    ExecuteRequest(request);

                }            
            }

            Console.ReadKey();
        }

        private static string ExecuteRequest(HttpWebRequest request)
        {
            try
            {
                var webResponse = request.GetResponse();
                var response = new StreamReader(webResponse.GetResponseStream()).ReadToEnd();


                Console.WriteLine($"Response: {response}");

                return response;
            }
            catch (WebException e)
            {
                Console.WriteLine($"Exception occurred: {e.Message}");
                Console.WriteLine($"Response: {new StreamReader(e.Response.GetResponseStream()).ReadToEnd()}");

                return String.Empty;
            }
        }

        private static string CleanInput(string strIn)
        {
            // Replace invalid characters with empty strings.
            try {
            return Regex.Replace(strIn, @"[^\w\.@-]", "", 
                                    RegexOptions.None, TimeSpan.FromSeconds(1.5)); 
            }
            // If we timeout when replacing invalid characters, 
            // we should return Empty.
            catch (RegexMatchTimeoutException) {
            return String.Empty;   
            }
        }        

        public class RequestSigner
        {
            private static readonly IDictionary<string, List<string>> RequiredHeaders = new Dictionary<string, List<string>>
            {
                { "GET", new List<string>{"date", "(request-target)", "host" }},
                { "HEAD", new List<string>{"date", "(request-target)", "host" }},
                { "DELETE", new List<string>{"date", "(request-target)", "host" }},
                { "PUT", new List<string>{"date", "(request-target)", "host", "content-length", "content-type", "x-content-sha256" }},
                { "POST", new List<string>{"date", "(request-target)", "host", "content-length", "content-type", "x-content-sha256" }},
                { "PUT-LESS", new List<string>{"date", "(request-target)", "host" }}
            };

            private readonly string keyId;
            private readonly ISigner signer;

            /// <summary>
            /// Adds the necessary authorization header for signed requests to Oracle Cloud Infrastructure services.
            /// Documentation for request signatures can be found here: https://docs.cloud.oracle.com/Content/API/Concepts/signingrequests.htm
            /// </summary>
            /// <param name="tenancyId">The tenancy OCID</param>
            /// <param name="userId">The user OCID</param>
            /// <param name="fingerprint">The fingerprint corresponding to the provided key</param>
            /// <param name="privateKeyPath">Path to a PEM file containing a private key</param>
            /// <param name="privateKeyPassphrase">An optional passphrase for the private key</param>
            public RequestSigner(string tenancyId, string userId, string fingerprint, string privateKeyPath, string privateKeyPassphrase="")
            {
                // This is the keyId for a key uploaded through the console
                this.keyId = $"{tenancyId}/{userId}/{fingerprint}";

                AsymmetricCipherKeyPair keyPair;
                using (var fileStream = File.OpenText(privateKeyPath))
                {
                    try {
                        keyPair = (AsymmetricCipherKeyPair)new PemReader(fileStream, new Password(privateKeyPassphrase.ToCharArray())).ReadObject();
                    }
                    catch (InvalidCipherTextException) {
                        throw new ArgumentException("Incorrect passphrase for private key");
                    }
                }

                RsaKeyParameters privateKeyParams = (RsaKeyParameters)keyPair.Private;
                this.signer = SignerUtilities.GetSigner("SHA-256withRSA");
                this.signer.Init(true, privateKeyParams);
            }

            public void SignRequest(HttpWebRequest request, bool useLessHeadersForPut = false)
            {
                if (request == null) { throw new ArgumentNullException(nameof(request)); }

                // By default, request.Date is DateTime.MinValue, so override to DateTime.UtcNow, but preserve the value if caller has already set the Date
                if (request.Date == DateTime.MinValue) { request.Date = DateTime.UtcNow; }

                var requestMethodUpper = request.Method.ToUpperInvariant();
                var requestMethodKey = useLessHeadersForPut ? requestMethodUpper + "-LESS" : requestMethodUpper;

                List<string> headers;
                if (!RequiredHeaders.TryGetValue(requestMethodKey, out headers)) {
                    throw new ArgumentException($"Don't know how to sign method: {request.Method}");
                }

                // for PUT and POST, if the body is empty we still must explicitly set content-length = 0 and x-content-sha256
                // the caller may already do this, but we shouldn't require it since we can determine it here
                if (request.ContentLength <= 0 && (string.Equals(requestMethodUpper, "POST") || string.Equals(requestMethodUpper, "PUT")))
                {
                    request.ContentLength = 0;
                    request.Headers["x-content-sha256"] = Convert.ToBase64String(SHA256.Create().ComputeHash(new byte[0]));
                }

                var signingStringBuilder = new StringBuilder();
                var newline = string.Empty;
                foreach (var headerName in headers)
                {
                    string value = null;
                    switch (headerName)
                    {
                        case "(request-target)":
                            value = buildRequestTarget(request);
                            break;
                        case "host":
                            value = request.Host;
                            break;
                        case "content-length":
                            value = request.ContentLength.ToString();
                            break;
                        default:
                            value = request.Headers[headerName];
                            break;
                    }

                    if (value == null) { throw new ArgumentException($"Request did not contain required header: {headerName}"); }
                    signingStringBuilder.Append(newline).Append($"{headerName}: {value}");
                    newline = "\n";
                }

                // generate signature using the private key
                var bytes = Encoding.UTF8.GetBytes(signingStringBuilder.ToString());
                this.signer.BlockUpdate(bytes, 0, bytes.Length);
                var signature = Convert.ToBase64String(this.signer.GenerateSignature());
                var authorization = $@"Signature version=""1"",headers=""{string.Join(" ", headers)}"",keyId=""{keyId}"",algorithm=""rsa-sha256"",signature=""{signature}""";
                request.Headers["authorization"] = authorization;
            }

            private static string buildRequestTarget(HttpWebRequest request)
            {
                // ex. get /20160918/instances
                return $"{request.Method.ToLowerInvariant()} {request.RequestUri.PathAndQuery}";
            }
        }

        /// <summary>
        /// Implements Bouncy Castle's IPasswordFinder interface to allow opening password protected private keys.
        /// </summary>
        public class Password : IPasswordFinder
        {
            private readonly char[] password;

            public Password(char[] password) { this.password = password; }

            public char[] GetPassword() { return (char[])password.Clone(); }
        }

    }
}