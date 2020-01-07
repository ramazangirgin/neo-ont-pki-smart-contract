using System;
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace io.certledger.smartcontract.platform.netcore
{
    public class NetCoreSignatureValidator
    {
     
        public static bool Validate(SignedData signedData)
        {
            AsymmetricKeyParameter publicKeyParameter = decodePublicKeyParameter(signedData.subjectPublicKeyInfo);
            AlgorithmIdentifier signatureAlgorithm = decodeSignatureAlgorithm(signedData.signatureAlgorithm);
            var verifier = new Asn1VerifierFactory(signatureAlgorithm, publicKeyParameter);
            return verify(verifier, signatureAlgorithm, signedData.signedData, signedData.signatureValue);
        }

        public static bool CheckECDSASha256Signature(byte[] signature, byte[] signed, byte[] publicKey)
        {
            string signatureAlg = "SHA-256withECDSA";
            return CheckSignature(signatureAlg, signature, signed, publicKey);
        }
        
        public static bool CheckRSAPSSSha256Signature(byte[] signature, byte[] signed, byte[] publicKey)
        {
            string signatureAlg = "SHA256withRSA/PSS";
            return CheckSignature(signatureAlg, signature, signed, publicKey);
        }

        private static bool CheckSignature(string signatureAlg, byte[] signature, byte[] signed, byte[] publicKey)
        {
            ISigner signer = SignerUtilities.GetSigner(signatureAlg);
            AsymmetricKeyParameter asymmetricKeyParameter = decodePublicKeyParameter(publicKey);
            signer.Init(false, asymmetricKeyParameter);
            signer.BlockUpdate(signed, 0, signed.Length);
            bool verified = false;

            try
            {
                verified = signer.VerifySignature(signature);
            }
            catch (Exception ex)
            {
                Logger.log("Error while verifying signature");
                Logger.log(ex.Message);
                verified = false;
            }

            return verified;
        }


        private static bool verify(IVerifierFactory verifier, AlgorithmIdentifier signatureAlgorithm, byte[] signedData,
            byte[] signature)
        {
            IStreamCalculator streamCalculator = verifier.CreateCalculator();

            byte[] b = signedData;

            streamCalculator.Stream.Write(b, 0, b.Length);

            //Platform.Dispose(streamCalculator.Stream);

            return ((IVerifier) streamCalculator.GetResult()).IsVerified(signature);
        }

        private static SubjectPublicKeyInfo decodeSubjectPublicKeyInfo(byte[] encodedSubjectPublicKeyInfo)
        {
            Asn1StreamParser asn1StreamParser = new Asn1StreamParser(encodedSubjectPublicKeyInfo);
            DerSequenceParser asn1SequenceParser = (DerSequenceParser) asn1StreamParser.ReadObject();
            Asn1Object subjectPublicKeyInfoAsnObject = (Asn1Object) asn1SequenceParser.ToAsn1Object();
            return SubjectPublicKeyInfo.GetInstance(subjectPublicKeyInfoAsnObject);
        }

        private static AsymmetricKeyParameter decodePublicKeyParameter(byte[] encodedSubjectPublicKeyInfo)
        {
            Asn1StreamParser asn1StreamParser = new Asn1StreamParser(encodedSubjectPublicKeyInfo);
            DerSequenceParser asn1SequenceParser = (DerSequenceParser) asn1StreamParser.ReadObject();
            Asn1Object subjectPublicKeyInfoAsnObject = (Asn1Object) asn1SequenceParser.ToAsn1Object();
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(subjectPublicKeyInfoAsnObject);
            return PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
        }

        private static AlgorithmIdentifier decodeSignatureAlgorithm(byte[] encodedSignatureAlgorithm)
        {
            Asn1StreamParser asn1StreamParser = new Asn1StreamParser(encodedSignatureAlgorithm);
            DerSequenceParser asn1SequenceParser = (DerSequenceParser) asn1StreamParser.ReadObject();
            Asn1Object subjectPublicKeyInfoAsnObject = (Asn1Object) asn1SequenceParser.ToAsn1Object();
            return AlgorithmIdentifier.GetInstance(subjectPublicKeyInfoAsnObject);
        }
    }
}