using System.Numerics;

namespace CertLedgerBusinessSCTemplate.src.io.certledger
{
    public class Certificate
    {
        public bool IsLoaded;
        public byte[] EncodedValue;
        public int Version;
        public byte[] TBSSignatureAlgorithm;
        public BigInteger SerialNumber;
        public Name Issuer;
        public Name Subject;
        public Validity Validity;

        public KeyUsage KeyUsage;
        public BasicConstraints BasicConstraints;

        public SubjectKeyIdentifier SubjectKeyIdentifier;
        public AuthorityKeyIdentifier AuthorityKeyIdentifier;
        public ExtendedKeyUsage ExtendedKeyUsage;

        public byte[][] DNsNames;
        public byte[][] EmailAddresses;
        public byte[][] IpAddresses;
        public byte[][] Urls;

        public byte[] TbsCertificate;
        public byte[] SignatureAlgorithm;
        public byte[] Signature;
        public byte[] SubjectPublicKeyInfo;
        public byte[] PublicKeyAlgName;

        public bool containsUnknownCriticalExtension;


        //todo: fill in parse method
        /*
         *  A
   certificate-using system MUST reject the certificate if it encounters
   a critical extension it does not recognize or a critical extension
   that contains information that it cannot process.
         */
        public bool hasSameExtensionTwice;
        //todo: fill in parse method
        /*
         * A certificate MUST NOT include more
   than one instance of a particular extension.
         */
    }

    public class BasicConstraints // extension
    {
        public bool HasPathLengthConstraint;
        public bool HasBasicConstraints;
        public bool IsCa;
        public int MaxPathLen;
    }

    public class KeyUsage //extension
    {
        public bool HasKeyUsageExtension;
        public bool IsCritical;
        public KeyUsageFlags KeyUsageFlags;
    }

    public class SubjectKeyIdentifier //extension
    {
        public bool HasSubjectKeyIdentifierExtension;
        public bool IsCritical;
        public byte[] keyIdentifier;
    }

    public class AuthorityKeyIdentifier // extension
    {
        public bool HasAuthorityKeyIdentifier;
        public bool IsCritical;
        public byte[] keyIdentifier;
    }


    public class Validity
    {
        public long NotBefore;
        public long NotAfter;
    }

    public class ExtendedKeyUsage //extension
    {
        public bool HasExtendedKeyUsageExtension;
        public bool IsCritical;
        public byte[][] Oids;
    }

    public class Name
    {
        public byte[] CommonName;
        public byte[] Country;
        public byte[] Organization;
        public byte[][] OrganizationalUnit;
        public byte[] Locality;
        public byte[][] StreetAddress;
        public byte[][] Province;
        public byte[][] PostalCode;
        public byte[] SerialNumber;
        public bool isEmpty;
    }

    public enum KeyUsageFlags
    {
        None = 0,
        EncipherOnly = 1,
        CrlSign = 2,
        KeyCertSign = 4,
        KeyAgreement = 8,
        DataEncipherment = 16, // 0x00000010
        KeyEncipherment = 32, // 0x00000020
        NonRepudiation = 64, // 0x00000040
        DigitalSignature = 128, // 0x00000080
        DecipherOnly = 32768, // 0x00008000
    }
}