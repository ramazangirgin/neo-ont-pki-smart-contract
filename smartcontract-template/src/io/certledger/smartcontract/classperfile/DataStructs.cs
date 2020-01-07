using System.Numerics;

namespace io.certledger.smartcontract.business
{
    public struct BasicConstraints
    {
        public bool HasPathLengthConstraint;
        public bool HasBasicConstraints;
        public bool IsCa;
        public int MaxPathLen;
    }

    public struct KeyUsage
    {
        public bool HasKeyUsageExtension;
        public bool IsCritical;
        public KeyUsageFlags KeyUsageFlags;
    }

    public struct SubjectKeyIdentifier
    {
        public bool HasSubjectKeyIdentifierExtension;
        public bool IsCritical;
        public byte[] keyIdentifier;
    }

    public struct AuthorityKeyIdentifier
    {
        public bool HasAuthorityKeyIdentifier;
        public bool IsCritical;

        public byte[] keyIdentifier;
        //fixme: add issues serial later
    }


    public struct Validity
    {
        public long NotBefore;
        public long NotAfter;
    }

    public struct ExtendedKeyUsage
    {
        public bool HasExtendedKeyUsageExtension;
        public bool IsCritical;
        public byte[][] Oids;
        public int Count;
    }

    //https://golang.org/pkg/crypto/x509/
    public struct Certificate
    {
        public bool IsLoaded;
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

        // Subject Alternate Name values. (Note that these values may not be valid

        // if invalid values were contained within a parsed certificate. For

        // example, an element of DNSNames may not be a valid DNS domain name.)
        public byte[][] DNsNames;
        public byte[][] EmailAddresses;
        public byte[][] IpAddresses;
        public byte[][] Urls;

        public byte[] TbsCertificate;
        public byte[] SignatureAlgorithm;
        public byte[] Signature;
        public byte[] SubjectPublicKeyInfo;
    }

    public struct Name
    {
        public byte[] CommonName;
        public byte[] Country;
        public byte[] Organization;
        public byte[][] OrganizationalUnit;
        public byte[] Locality;
        public byte[][] Province;
        public byte[][] StreetAddress;
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