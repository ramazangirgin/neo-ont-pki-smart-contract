using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;

namespace io.certledger.smartcontract.business
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

        private static bool verify(IVerifierFactory verifier, AlgorithmIdentifier signatureAlgorithm, byte[] signedData, byte[] signature)
        {
            IStreamCalculator streamCalculator = verifier.CreateCalculator();

            byte[] b = signedData;

            streamCalculator.Stream.Write(b, 0, b.Length);

            //Platform.Dispose(streamCalculator.Stream);

            return ((IVerifier) streamCalculator.GetResult()).IsVerified(signature);
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