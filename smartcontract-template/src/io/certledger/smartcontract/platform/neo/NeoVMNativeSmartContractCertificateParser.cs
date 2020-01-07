using System.Numerics;
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Helper = Neo.SmartContract.Framework.Helper;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo
{
    public class NeoVMNativeSmartContractCertificateParser
    {
        public static readonly byte[] parseContractAddr =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x08
        };

        public static Certificate parse(byte[] encodedCertValue)
        {
            ParseCertParam param = new ParseCertParam { };
            param.asnData = encodedCertValue;
            byte[] parsedData = callNativeContract(param);
            CertificateStr cert = Deserialization.deserializeCertData(parsedData);
            Certificate certificate = NativeMapper.converyNativeCert(cert, encodedCertValue);
            return certificate;
        }

        private static byte[] callNativeContract(ParseCertParam param)
        {
            byte[] ret = Native.Invoke(0, parseContractAddr, "parseCert", param);

            return ret;
        }

        public struct ParseCertParam
        {
            public byte[] asnData;
        }
    }

    #region Main Structures

    /*
     * Certificate Structure
     */
    public class CertificateStr
    {
        public bool IsLoaded;
        public int Version;
        public byte[] SerialNumber;
        public NameStr issuer;
        public NameStr subject;
        public Validity Validity;
        public NativeKeyUsage KeyUsage;
        public BasicConstraints BasicConstraints;
        public AuthorityKeyIdentifier AuthorityKeyIdentifier;
        public SubjectKeyIdentifier SubjectKeyIdentifier;
        public NativeExtendedKeyUsage ExtendedKeyUsage;
        public CMap<int, string> DnsNames;
        public CMap<int, string> EmailAddresses;
        public CMap<int, string> IpAddresses;
        public CMap<int, string> Urls;

        public byte[] TbsCertificate;
        public byte[] SignatureAlgorithm;
        public byte[] Signature;
        public byte[] SubjectPublicKeyInfo;
        public byte[] PublicKeyAlgName;
        public byte[] TBSSignatureAlgorithm;
    }

    public class NativeMapper
    {
        public static byte[][] convertStringMapToArray(CMap<int, string> sMap)
        {
            byte[][] arr = new byte[sMap.size][];
            for (int i = 0; i < sMap.size; ++i)
            {
                arr[i] = Helper.AsByteArray(sMap.map[i]);
            }

            return arr;
        }

        public static Certificate converyNativeCert(CertificateStr nativeCert, byte[] encodedCertValue)
        {
            Certificate certificate = new Certificate();

            certificate.AuthorityKeyIdentifier = nativeCert.AuthorityKeyIdentifier;
            certificate.BasicConstraints = nativeCert.BasicConstraints;
            certificate.DNsNames = convertStringMapToArray(nativeCert.DnsNames);
            certificate.EmailAddresses = convertStringMapToArray(nativeCert.EmailAddresses);
            certificate.ExtendedKeyUsage = convertExtendedKeyUsage(nativeCert.ExtendedKeyUsage);
            certificate.IpAddresses = convertStringMapToArray(nativeCert.IpAddresses);
            certificate.Issuer = convertNativeName(nativeCert.issuer);
            certificate.Subject = convertNativeName(nativeCert.subject);
            certificate.KeyUsage = convertKeyUsage(nativeCert.KeyUsage);
            certificate.PublicKeyAlgName = nativeCert.PublicKeyAlgName;
            certificate.SerialNumber = Helper.AsBigInteger(nativeCert.SerialNumber); // todo : possibly problematic
            certificate.Signature = nativeCert.Signature;
            certificate.SignatureAlgorithm = nativeCert.SignatureAlgorithm;
            certificate.SubjectKeyIdentifier = nativeCert.SubjectKeyIdentifier;
            certificate.SubjectPublicKeyInfo = nativeCert.SubjectPublicKeyInfo;
            certificate.TbsCertificate = nativeCert.TbsCertificate;
            certificate.TBSSignatureAlgorithm = nativeCert.TBSSignatureAlgorithm;
            certificate.Urls = convertStringMapToArray(nativeCert.Urls);
            certificate.Validity = nativeCert.Validity;
            certificate.Version = nativeCert.Version;
            certificate.IsLoaded = true;
            certificate.EncodedValue = encodedCertValue;
            return certificate;
        }

        public static Name convertNativeName(NameStr nativeName)
        {
            Name name = new Name();

            name.CommonName = nativeName.CommonName;
            // TODO : add remaining fields
            return name;
        }

        public static KeyUsageFlags convertIntToKeyUsageFlag(int value)
        {
            KeyUsageFlags flag = KeyUsageFlags.None;

            if ((value & (int) NativeKeyUsageFlags.DigitalSignature) > 0)
            {
                flag |= KeyUsageFlags.DigitalSignature;
            }

            if ((value & (int) NativeKeyUsageFlags.NonRepudation) > 0)
            {
                flag |= KeyUsageFlags.NonRepudiation;
            }

            if ((value & (int) NativeKeyUsageFlags.KeyEncipherment) > 0)
            {
                flag |= KeyUsageFlags.KeyEncipherment;
            }

            if ((value & (int) NativeKeyUsageFlags.DataEncipherment) > 0)
            {
                flag |= KeyUsageFlags.DataEncipherment;
            }

            if ((value & (int) NativeKeyUsageFlags.KeyAgreement) > 0)
            {
                flag |= KeyUsageFlags.KeyAgreement;
            }

            if ((value & (int) NativeKeyUsageFlags.KeyCertSign) > 0)
            {
                flag |= KeyUsageFlags.KeyCertSign;
            }

            if ((value & (int) NativeKeyUsageFlags.CRLSign) > 0)
            {
                flag |= KeyUsageFlags.CrlSign;
            }

            if ((value & (int) NativeKeyUsageFlags.EncipherOnly) > 0)
            {
                flag |= KeyUsageFlags.EncipherOnly;
            }

            if ((value & (int) NativeKeyUsageFlags.DecipherOnly) > 0)
            {
                flag |= KeyUsageFlags.DecipherOnly;
            }

            return flag;
        }

        public static KeyUsage convertKeyUsage(NativeKeyUsage nativeKeyUsage)
        {
            KeyUsage keyUsage = new KeyUsage();
            keyUsage.HasKeyUsageExtension = nativeKeyUsage.HasKeyUsageExtension;
            keyUsage.IsCritical = nativeKeyUsage.IsCritical;
            keyUsage.KeyUsageFlags = convertIntToKeyUsageFlag(nativeKeyUsage.Value);
            return keyUsage;
        }

        public static ExtendedKeyUsage convertExtendedKeyUsage(NativeExtendedKeyUsage nativeExtendedKeyUsage)
        {
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
            extendedKeyUsage.HasExtendedKeyUsageExtension = nativeExtendedKeyUsage.HasExtendedKeyUsageExtension;
            extendedKeyUsage.IsCritical = nativeExtendedKeyUsage.IsCritical;
            extendedKeyUsage.Oids = convertStringMapToArray(nativeExtendedKeyUsage.Oids);
            return extendedKeyUsage;
        }
    }

    public enum NativeKeyUsageFlags
    {
        DigitalSignature = 0x01,
        NonRepudation = 0x02,
        KeyEncipherment = 0x04,
        DataEncipherment = 0x08,
        KeyAgreement = 0x10,
        KeyCertSign = 0x20,
        CRLSign = 0x40,
        EncipherOnly = 0x80,
        DecipherOnly = 0x0100
    }

    public class NativeKeyUsage
    {
        public bool HasKeyUsageExtension;
        public bool IsCritical;
        public int Value;
    }

    public class NativeExtendedKeyUsage
    {
        public bool HasExtendedKeyUsageExtension;
        public bool IsCritical;
        public CMap<int, string> Oids;
        public int Count;
    }

    /*
     * Name Structure
     */
    public class NameStr
    {
        public byte[] CommonName;
        public CMap<int, string> Country;
        public CMap<int, string> Organization;
        public CMap<int, string> OrganizationalUnit;
        public CMap<int, string> Locality;
        public CMap<int, string> Province;
        public CMap<int, string> StreetAddress;
        public CMap<int, string> PostalCode;
        public string SerialNumber;
        public bool isEmpty;
    }

    #endregion


    /*
     * Map wrapper to support size.
     */
    public struct CMap<TKey, TValue>
    {
        public Map<TKey, TValue> map;
        public int size;
    }

    public class Deserialization
    {
        #region byte util methods

        /*
         * 2 bytes data read for ushort
         */
        public static BigInteger GetBigInteger(byte[] data)
        {
            byte[] zero = new byte[] {0x00};
            byte[] temp = Helper.Concat(data, zero);

            BigInteger val = Helper.AsBigInteger(temp);

            return val;
        }

        public static short readShort(byte[] data, int idx)
        {
            byte[] leading = Helper.Range(data, idx, 2);

            BigInteger val = GetBigInteger(leading);

            return (short) val;
        }

        /*
         * 4 bytes data read for uint (little endian)
         */
        public static int readInt(byte[] data, int idx)
        {
            byte[] leading = Helper.Range(data, idx, 4);
            BigInteger val = GetBigInteger(leading);

            return (int) val;
        }

        /*
         * 8 bytes data read for ulong (little endian)
         */
        public static long readLong(byte[] data, int idx)
        {
            byte[] leading = Helper.Range(data, idx, 8);
            BigInteger val = GetBigInteger(leading);

            return (long) val;
        }

        public static bool readBool(byte[] data, int idx)
        {
            return (data[idx] & 0xFF) > 0;
        }

        /*
         * Read byte[] as a string. At most 9 octets are data size. See readByteArray()
         */
        public static DeserializationFieldResult readString(byte[] data, int idx)
        {
            DeserializationFieldResult res = readByteArray(data, idx);
            if (res.isEmpty)
            {
                return res;
            }

            //else
            res.value = Helper.AsString((byte[]) res.value);

            return res;
        }

        /*
         * Read byte[] as a string array. At most 9 octets reveal the size of the array (string element count).
         */
        public static DeserializationFieldResult readStringArray(byte[] data, int idx)
        {
            DeserializationFieldResult res = new DeserializationFieldResult { };
            CMap<int, string> map = new CMap<int, string> { };
            map.map = new Map<int, string>();

            VarSizeStr countStr = readVarSize(data, idx);
            res.size = countStr.size;
            if (countStr.value == 0)
            {
                map.size = 0;
                res.value = map;
                res.isEmpty = true;
                return res;
            }

            idx += countStr.size;
            map.size = (int) countStr.value;
            for (int i = 0; i < map.size; ++i)
            {
                DeserializationFieldResult tempStr = readString(data, idx);

                map.map[i] = (string) tempStr.value;
                res.size = res.size + tempStr.size;
                idx += tempStr.size;
            }

            res.value = map;
            res.isEmpty = false;
            return res;
        }

        /*
         * Read byte[] from the stream. At most 9 octets reveal the size of the array.
         */
        public static DeserializationFieldResult readByteArray(byte[] data, int idx)
        {
            DeserializationFieldResult res = new DeserializationFieldResult();
            res.size = 0;
            res.value = null;

            VarSizeStr varSizeStr = readVarSize(data, idx);
            if (varSizeStr.value == 0)
            {
                res.isEmpty = true;
                res.size = 1;
                return res;
            }

            res.size = varSizeStr.size + varSizeStr.value;
            res.value = Helper.Range(data, idx + varSizeStr.size, varSizeStr.value);

            return res;
        }
        /*
         * Generic structure for array size. Each array structure begins with the leading size structure.
         * Size can be a octet, byte, uint or ulong, total size of this structure depends on the type of
         * the data, so size becomes 1, 3, 5, 9 byte(s) respectively.
         */

        public static VarSizeStr readVarSize(byte[] data, int idx)
        {
            byte[] temp = Helper.Range(data, idx, 1);
            byte[] temp2 = new byte[] {0x00};
            byte[] temp3 = Helper.Concat(temp, temp2);
            BigInteger temp4 = Helper.AsBigInteger(temp3);
            int ind = (int) temp4;

            byte[] val = new byte[1];
            int size = 0;

            if (ind == 0xfd)
            {
                // read next 2 bytes total 3 (ushort length string)
                size = 2;
                val = new byte[3];
            }

            if (ind == 0xfe)
            {
                // read next 4 bytes total 5 (uint length string)
                size = 4;
                val = new byte[5];
            }

            if (ind == 0xff)
            {
                // read next 8 bytes total 9 (ulong length string)
                size = 8;
                val = new byte[9];
            }

            if (size > 0)
            {
                val = Helper.Range(data, idx + 1, size);

                val = Helper.Concat(val, temp2);
            }

            VarSizeStr res = new VarSizeStr();
            if (size == 0)
            {
                res.value = ind;
            }

            if (size > 0)
            {
                res.value = (int) Helper.AsBigInteger(val);
            }

            res.size = size + 1;

            return res;
        }

        #endregion

        #region cert deserialize methods

        public static CertificateStr deserializeCertData(byte[] raw)
        {
            int length = raw.Length;
            int idx = 0;
            CertificateStr cert = new CertificateStr();

            cert.Version = readInt(raw, idx);
            idx += 4;

            DeserializationFieldResult serialNumber = readByteArray(raw, idx);
            cert.SerialNumber = (byte[]) serialNumber.value;
            idx += serialNumber.size;

            DeserializationFieldResult issuer = deserializeName(raw, idx);
            cert.issuer = (NameStr) issuer.value;
            idx += issuer.size;

            DeserializationFieldResult subject = deserializeName(raw, idx);
            cert.subject = (NameStr) subject.value;
            idx += subject.size;

            Validity validity = new Validity();
            validity.NotBefore = readLong(raw, idx); //check
            idx += 8;

            validity.NotAfter = readLong(raw, idx); //check
            idx += 8;
            cert.Validity = validity;

            NativeExtendedKeyUsage extendedKeyUsage = new NativeExtendedKeyUsage();
            extendedKeyUsage.Count = readInt(raw, idx);
            idx += 4;

            DeserializationFieldResult extendedKeyUsageOIDs = readStringArray(raw, idx);
            extendedKeyUsage.Oids = (CMap<int, string>) extendedKeyUsageOIDs.value;
            idx += extendedKeyUsageOIDs.size;
            cert.ExtendedKeyUsage = extendedKeyUsage;

            NativeKeyUsage keyUsage = new NativeKeyUsage();
            keyUsage.Value = readInt(raw, idx);
            idx += 4;
            cert.KeyUsage = keyUsage;

            BasicConstraints basicConstraints = new BasicConstraints();
            basicConstraints.HasBasicConstraints = readBool(raw, idx);
            idx += 1;

            basicConstraints.IsCa = readBool(raw, idx);
            idx += 1;

            basicConstraints.MaxPathLen = readInt(raw, idx); //check FF FF FF FF becomes FF FF FE FE
            idx += 4;
            cert.BasicConstraints = basicConstraints;

            AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
            DeserializationFieldResult authorityKeyId = readByteArray(raw, idx);
            authorityKeyIdentifier.keyIdentifier = (byte[]) authorityKeyId.value;
            if (authorityKeyId.size > 2)
            {
                authorityKeyIdentifier.HasAuthorityKeyIdentifier = true;
            }

            idx += authorityKeyId.size;
            cert.AuthorityKeyIdentifier = authorityKeyIdentifier;

            SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
            DeserializationFieldResult subjectKeyId = readByteArray(raw, idx);
            subjectKeyIdentifier.keyIdentifier = (byte[]) subjectKeyId.value;
            if (subjectKeyId.size > 2)
            {
                subjectKeyIdentifier.HasSubjectKeyIdentifierExtension = true;
            }

            idx += subjectKeyId.size;
            cert.SubjectKeyIdentifier = subjectKeyIdentifier;

            DeserializationFieldResult dnsNames = readStringArray(raw, idx);
            cert.DnsNames = (CMap<int, string>) dnsNames.value;
            idx += dnsNames.size;

            DeserializationFieldResult emailAddresses = readStringArray(raw, idx);
            cert.EmailAddresses = (CMap<int, string>) emailAddresses.value;
            idx += emailAddresses.size;

            DeserializationFieldResult ipAddresses = readStringArray(raw, idx);
            cert.IpAddresses = (CMap<int, string>) ipAddresses.value;
            idx += ipAddresses.size;

            DeserializationFieldResult urls = readStringArray(raw, idx);
            cert.Urls = (CMap<int, string>) urls.value;
            idx += urls.size;

            DeserializationFieldResult tbsCertificate = readByteArray(raw, idx);
            cert.TbsCertificate = (byte[]) tbsCertificate.value;
            idx += tbsCertificate.size;

            DeserializationFieldResult signatureAlgorithm = readByteArray(raw, idx);
            cert.SignatureAlgorithm = (byte[]) signatureAlgorithm.value;
            idx += signatureAlgorithm.size;

            DeserializationFieldResult signatureValue = readByteArray(raw, idx);
            cert.Signature = (byte[]) signatureValue.value;
            idx += signatureValue.size;

            DeserializationFieldResult subjectPublicKeyInfo = readByteArray(raw, idx);
            cert.SubjectPublicKeyInfo = (byte[]) subjectPublicKeyInfo.value;
            idx += subjectPublicKeyInfo.size;

            DeserializationFieldResult publicKeySignatureAlgorithm = readByteArray(raw, idx);
            cert.PublicKeyAlgName = (byte[]) publicKeySignatureAlgorithm.value;
            idx += publicKeySignatureAlgorithm.size;

            DeserializationFieldResult tbsCertificateSignatureAlgorithm = readByteArray(raw, idx);
            cert.TBSSignatureAlgorithm = (byte[]) tbsCertificateSignatureAlgorithm.value;
            idx += tbsCertificateSignatureAlgorithm.size;

            // todo return byte[] ?
            return cert;
        }

        public static DeserializationFieldResult deserializeName(byte[] data, int idx)
        {
            int initial = idx;
            NameStr name = new NameStr();

            DeserializationFieldResult commonName = readByteArray(data, idx);
            name.CommonName = (byte[]) commonName.value;
            idx += commonName.size;

            DeserializationFieldResult country = readStringArray(data, idx);
            name.Country = (CMap<int, string>) country.value;
            idx += country.size;

            DeserializationFieldResult organization = readStringArray(data, idx);
            name.Organization = (CMap<int, string>) organization.value;
            idx += organization.size;

            DeserializationFieldResult organizationalUnit = readStringArray(data, idx);
            name.OrganizationalUnit = (CMap<int, string>) organizationalUnit.value;
            idx += organizationalUnit.size;

            DeserializationFieldResult locality = readStringArray(data, idx);
            name.Locality = (CMap<int, string>) locality.value;
            idx += locality.size;

            DeserializationFieldResult province = readStringArray(data, idx);
            name.Province = (CMap<int, string>) province.value;
            idx += province.size;

            DeserializationFieldResult streetAddress = readStringArray(data, idx);
            name.StreetAddress = (CMap<int, string>) streetAddress.value;
            idx += streetAddress.size;

            DeserializationFieldResult postalCode = readStringArray(data, idx);
            name.PostalCode = (CMap<int, string>) postalCode.value;
            idx += postalCode.size;

            DeserializationFieldResult serialNumber = readString(data, idx);
            name.SerialNumber = (string) serialNumber.value;
            idx += serialNumber.size;

            DeserializationFieldResult res = new DeserializationFieldResult { };
            res.value = name;
            res.size = idx - initial;
            return res;
        }

        public static byte[][] convertStringMapToArray(CMap<int, string> sMap)
        {
            byte[][] arr = new byte[sMap.size][];
            for (int i = 0; i < sMap.size; ++i)
            {
                arr[i] = Helper.AsByteArray(sMap.map[i]);
            }

            return arr;
        }

        #endregion
    }

    public struct DeserializationFieldResult
    {
        public object value;

        public int size;
        public bool isEmpty;
    }

    public struct VarSizeStr
    {
        public int size;
        public int value;
    }

    public class PrintStr
    {
        public static void print(CertificateStr cert)
        {
            Runtime.Notify("test", "version", 0, cert.Version);
            Runtime.Notify("test", "serialNumber", 1, cert.SerialNumber);
            print(cert.issuer, "issuer");
            print(cert.subject, "subject");
            Runtime.Notify("test", "notBefore", 2, cert.Validity.NotBefore);
            Runtime.Notify("test", "notAfter", 2, cert.Validity.NotAfter);
            Runtime.Notify("test", "extendedKeyUsageCount", 0, cert.ExtendedKeyUsage.Count);
            print(cert.ExtendedKeyUsage.Oids, "extendedKeyUsageOids");
            Runtime.Notify("test", "keyUsage", 0, cert.KeyUsage.Value);
            Runtime.Notify("test", "basicContraintsValid", 3, cert.BasicConstraints.HasBasicConstraints);
            Runtime.Notify("test", "isCa", 3, cert.BasicConstraints.IsCa);
            Runtime.Notify("test", "maxPathLen", 0, cert.BasicConstraints.MaxPathLen);
            Runtime.Notify("test", "hasAuthorityKeyIdentifier", 3,
                cert.AuthorityKeyIdentifier.HasAuthorityKeyIdentifier);
            Runtime.Notify("test", "authorityKeyId", 1, cert.AuthorityKeyIdentifier.keyIdentifier);
            Runtime.Notify("test", "subjectKeyId", 1, cert.SubjectKeyIdentifier.keyIdentifier);

            print(cert.DnsNames, "dnsName");
            print(cert.EmailAddresses, "emailAddresses");
            print(cert.IpAddresses, "ipAddresses");
            print(cert.Urls, "urls");

            Runtime.Notify("test", "tbsCertificate", 1, cert.TbsCertificate);
            Runtime.Notify("test", "signatureAlgorithm", 1, cert.SignatureAlgorithm);
            Runtime.Notify("test", "signatureValue", 1, cert.Signature);
            Runtime.Notify("test", "subjectPublicKeyInfo", 1, cert.SubjectPublicKeyInfo);

            Runtime.Notify("test", "publicKeySignatureAlgorithm", 1, cert.PublicKeyAlgName);
            Runtime.Notify("test", "tbsCertificateSignatureAlgorithm", 1, cert.TBSSignatureAlgorithm);
        }

        public static void print(NameStr name, string prefix)
        {
            Runtime.Notify("test", prefix + "commonName", 4, name.CommonName);
            print(name.Country, prefix + "country");
            print(name.Organization, prefix + "organization");
            print(name.OrganizationalUnit, prefix + "organizationalUnit");
            print(name.Locality, prefix + "locality");
            print(name.Province, prefix + "province");
            print(name.StreetAddress, prefix + "streetAddress");
            print(name.PostalCode, prefix + "postalCode");
            Runtime.Notify("test", prefix + "serialNumber", 4, name.SerialNumber);
        }

        public static void print(CMap<int, string> map,
            string identifier)
        {
            int size = map.size;
            if (size == 0) return;

            for (int i = 0; i < size; ++i)
            {
                string val = map.map[i];
                Runtime.Notify("test", identifier, 4, val);
            }
        }
    }
}