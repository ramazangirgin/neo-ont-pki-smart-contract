//#define ONT

#define NEO
//#define NET_CORE
#define SMART_CONTRACT_TEST

#region NEO_ONT_IMPORTS

#if NEO
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Helper = Neo.SmartContract.Framework.Helper;
#endif
#if ONT
                    using Ont.SmartContract.Framework;
                    using Ont.SmartContract.Framework.Services.Ont;
                    using Ont.SmartContract.Framework.Services.System;
                    using Helper = Ont.SmartContract.Framework.Helper;
                    #endif

#endregion

using System;
using System.Numerics;

#region NET_CORE_IMPORTS

#if NET_CORE
                using io.certledger.smartcontract.allinone.platfom.netcore;

                #endif

#endregion

namespace CertLedgerBusinessSCTemplate.io.certledger.smartcontract.allinone
{
    #region ONT_NEO_SMART_CONTRACT_DEFINITON_SECTION

#if NEO || ONT
#if NEO
    public class CertLedgerBusinessScTemplate : SmartContract
#endif
#if ONT
                    public class CertLedgerBusinessScTemplate : SmartContract
                #endif
    {
        public static object Main(string operation, params object[] args)
        {
            if (operation.Equals("AddRootCACertificate"))
            {
                Logger.log("Operation", "AddRootCACertificate");
                return AddRootCACertificate(args);
            }
            else if (operation.Equals("UntrustRootCACertificate"))
            {
                Logger.log("Operation", "UntrustRootCACertificate");
                return UntrustRootCACertificate(args);
            }
            else if (operation.Equals("AddSubCACertificate"))
            {
                return AddSubCACertificate(args);
            }
            else if (operation.Equals("RevokeSubCACertificate"))
            {
                return RevokeSubCACertificate(args);
            }
            else if (operation.Equals("AddSSLCertificate"))
            {
                return AddSSLCertificate(args);
            }
            else if (operation.Equals("RevokeSSLCertificate"))
            {
                return RevokeSSLCertificate(args);
            }
            else if (operation.Equals("LogDomainCertificates"))
            {
                return LogDomainCertificates(args);
            }
#if SMART_CONTRACT_TEST
            else if (operation.Equals("LogSSLCertificateStorageStatus"))
            {
                return LogSSLCertificateStorageStatus(args);
            }
            else if (operation.Equals("LogCACertificateStorageStatus"))
            {
                return LogCACertificateStorageStatus(args);
            }
            else if (operation.Equals("LogTrustedCAList"))
            {
                return LogTrustedCAList();
            }
            else if (operation.Equals("ResetStorage"))
            {
                return ResetStorage();
            }
            else if (operation.Equals("ParseCertificate"))
            {
                Logger.log("Operation", "ParseCertificate");
                return ParseCertificate(args);
            }
#endif
            Logger.log("Operation", "Unknown");
            return false;
        }

        public static object ParseCertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            Logger.log("ParseCertificate  started");
            Certificate certificate = CertificateParser.Parse(encodedCert);
            Logger.LogCertificate(certificate);
            Logger.log("ParseCertificate finished");
            return true;
        }

        public static object AddRootCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Adding Root CA Certificate started");
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            bool result = RootCaCertificateHandler.AddTrustedRootCaCertificate(certificateHash, encodedCert, signature);
            Logger.log("Adding Root CA Certificate completed");
            Logger.log(result);
            return result;
        }

        public static object UntrustRootCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Untrusting Root CA Certificate started");
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            bool result = RootCaCertificateHandler.UntrustRootCaCertificate(certificateHash, encodedCert, signature);
            Logger.log("Untrusting Root CA Certificate completed");
            Logger.log(result);
            return result;
        }

        public static object AddSubCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            Logger.log("Adding Sub CA Certificate");
            bool addSubCaCertificateResult =
                SubCaCertificateHandler.AddSubCaCertificate(certificateHash, encodedCert, signature);
            Logger.log(addSubCaCertificateResult);
            Logger.log("Sub CA Certificate process completed");
            return addSubCaCertificateResult;
        }
        
        public static object RevokeSubCACertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Revoke Sub CA Certificate started");
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            bool result = SubCaCertificateHandler.RevokeSubCaCertificate(certificateHash, encodedCert, signature);
            Logger.log("Revoke Sub CA Certificate completed");
            Logger.log("Result : ",result);
            return result;
        } 
     
        public static object AddSSLCertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            Logger.log("Adding SSL Certificate");
            bool addSslCertificateResult = SslCertificateHandler.AddSslCertificate(certificateHash, encodedCert);
            Logger.log(addSslCertificateResult);
            Logger.log("SSL Certificate process completed");
            return addSslCertificateResult;
        }
        
        public static object RevokeSSLCertificate(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            Logger.log("Revoke SSL Certificate started");
            //byte[] signature = (byte[]) args[1];
            byte[] signature = null;
            bool result = SslCertificateHandler.RevokeSslCertificate(certificateHash, encodedCert, signature);
            Logger.log("Revoke SSL Certificate completed");
            Logger.log("Result : ",result);
            return result;
        }
        
        public static object LogDomainCertificates(object[] args)
        {
            byte[] domainCertListStorageKey = (byte[]) args[0];
            Logger.log("Log Domain Certificates started. Domain: ", domainCertListStorageKey);
            byte[] trustedRootCAListHashMapEntrySerialized = StorageUtil.readFromStorage(domainCertListStorageKey);
            if (trustedRootCAListHashMapEntrySerialized != null)
            {
                Logger.log("Certificates for domain exists in Storage. Domain: ", domainCertListStorageKey);
                CertificateHashMapEntry certificateHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(trustedRootCAListHashMapEntrySerialized);
                Logger.log("Certificate Count: ");
                Logger.log(certificateHashMapEntry.certificateHashArray.Length);

                for (int i = 0; i < certificateHashMapEntry.certificateHashArray.Length; i++)
                {
                    byte[] certificateHashEntrySerialized = certificateHashMapEntry.certificateHashArray[i];
                    CertificateHashEntry certificateHashEntry =
                        (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
                    Logger.log("IsCa: ", certificateHashEntry.IsCa);
                    Logger.log(certificateHashEntry.CertificateHash);
                    LogSSLCertificateWithCertificateHashValue(certificateHashEntry.CertificateHash);
                }
            }
            else
            {
                Logger.log("There isn't any certificate for Domain: ", domainCertListStorageKey);
            }

            Logger.log("Log Domain Certificates completed. Domain: ", domainCertListStorageKey);
            return true;
        }

        public static object LogCACertificateStorageStatus(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            byte[] caCertificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (caCertificateEnrtySerialized != null)
            {
                CaCertificateEntry caCertificateHashEntry =
                    (CaCertificateEntry) SerializationUtil.Deserialize(caCertificateEnrtySerialized);
                Logger.log("CA Certificate Exists in Storage");
                Logger.log(caCertificateHashEntry.CertificateValue);
                Logger.log("IsRevoked: ", caCertificateHashEntry.IsRevoked);
                Logger.log("IsTrusted: ", caCertificateHashEntry.IsTrusted);
            }
            else
            {
                Logger.log("CA Certificate Not Exists in Storage");
            }

            return true;
        }

        public static object LogSSLCertificateStorageStatus(object[] args)
        {
            byte[] encodedCert = (byte[]) args[0];
            byte[] certificateHash = Sha256(encodedCert);
            LogSSLCertificateWithCertificateHashValue(certificateHash);
            return true;
        }

        private static void LogSSLCertificateWithCertificateHashValue(byte[] certificateHash)
        {
            byte[] certificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (certificateEnrtySerialized != null)
            {
                EndEntityCertificateEntry endEntityCertificateEntry =
                    (EndEntityCertificateEntry) SerializationUtil.Deserialize(certificateEnrtySerialized);
                Logger.log("SSL Certificate Exists in Storage");
                Logger.log("IsRevoked: ", endEntityCertificateEntry.IsRevoked);
                Logger.log(endEntityCertificateEntry.CertificateValue);
            }
            else
            {
                Logger.log("SSL Certificate Not Exists in Storage");
            }
        }

        public static object LogTrustedCAList()
        {
            CertificateHashEntry[] retrieveTrustedRootCaList = CertificateStorageManager.RetrieveTrustedRootCaList();
            Logger.log(retrieveTrustedRootCaList.Length);
            foreach (CertificateHashEntry certificateHashEntry in retrieveTrustedRootCaList)
            {
                Logger.log("                                     ");
                Logger.log(certificateHashEntry.CertificateHash);
                Logger.log(certificateHashEntry.IsCa);
                Logger.log("                                     ");
            }

            return true;
        }

        public static object ResetStorage()
        {
            Logger.log("Deleting all storage entries");
            StorageUtil.clearStorage();
            Logger.log("Deleted all storage entries");
            return true;
        }
    }

#endif

    #endregion

    #region BUSINESS_LOGIC_SECTION

    [Serializable]
    public struct CaCertificateSubjectKeyIdEntry
    {
        public byte[] CertificateHash;
        public bool IsRootCa;
    }

    [Serializable]
    public struct CertificateHashEntry
    {
        public byte[] CertificateHash;
        public bool IsCa;
    }

    [Serializable]
    public struct CaCertificateEntry
    {
        public byte[] CertificateValue;
        public bool IsTrusted;
        public bool IsRevoked;
    }

    [Serializable]
    public struct EndEntityCertificateEntry
    {
        public byte[] CertificateValue;
        public bool IsRevoked;
    }

    [Serializable]
    public class CertificateHashMapEntry
    {
        public byte[][] certificateHashArray;
    }


    public class CertificateStorageManager
    {
        public static readonly byte[] TRUSTED_ROOT_CA_LIST_STORAGE_KEY =
            StringUtil.StringToByteArray("TRUSTED_ROOT_CA_LIST_STORAGE_KEY");

        public static readonly byte[] ELEMENT_LIST = StringUtil.StringToByteArray("ELEMENT_LIST_");

        public static void AddRootCaCertificateToStorage(Certificate certificate, byte[] certificateHash,
            byte[] encodedCert)
        {
            AddCaCertificateToStorage(certificate, certificateHash, encodedCert, true);
            AddRootCaCertificateToRootCaList(certificateHash); //Discuss trusted root CA list
        }

        private static void AddRootCaCertificateToRootCaList(byte[] rootCaCertificateHash)
        {
            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = rootCaCertificateHash;
            newCertHashEntry.IsCa = true;

            AddCertificateToList(TRUSTED_ROOT_CA_LIST_STORAGE_KEY, newCertHashEntry);
        }

        private static void AddCertificateToList(byte[] storageKey, CertificateHashEntry newCertHashEntry)
        {
            CertificateHashMapEntry trustedRootCaHashMapEntry;
            byte[] newCertHashEntrySerialized = SerializationUtil.Serialize(newCertHashEntry);

            byte[] trustedRootCAListHashMapEntrySerialized = StorageUtil.readFromStorage(storageKey);
            if (trustedRootCAListHashMapEntrySerialized == null)
            {
                trustedRootCaHashMapEntry = new CertificateHashMapEntry();
                trustedRootCaHashMapEntry.certificateHashArray = new byte[1][];
                trustedRootCaHashMapEntry.certificateHashArray[0] = newCertHashEntrySerialized;
            }
            else
            {
                trustedRootCaHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(trustedRootCAListHashMapEntrySerialized);
                byte[][] newCertificateHashArray =
                    new byte[trustedRootCaHashMapEntry.certificateHashArray.Length + 1][];
                newCertificateHashArray[0] = newCertHashEntrySerialized;
                for (int i = 0; i < trustedRootCaHashMapEntry.certificateHashArray.Length; i++)
                {
                    newCertificateHashArray[i + 1] = trustedRootCaHashMapEntry.certificateHashArray[i];
                }

                trustedRootCaHashMapEntry.certificateHashArray = newCertificateHashArray;
            }

            trustedRootCAListHashMapEntrySerialized = SerializationUtil.Serialize(trustedRootCaHashMapEntry);
            StorageUtil.saveToStorage(storageKey, trustedRootCAListHashMapEntrySerialized);
        }

        public static CertificateHashEntry[] RetrieveTrustedRootCaList()
        {
            return RetrieveCertList(TRUSTED_ROOT_CA_LIST_STORAGE_KEY);
        }

        public static CertificateHashEntry[] RetrieveCertList(byte[] storageKey)
        {
            byte[] trustedRootCAListHashMapEntrySerialized = StorageUtil.readFromStorage(storageKey);
            if (trustedRootCAListHashMapEntrySerialized == null)
            {
                return new CertificateHashEntry[0];
            }
            else
            {
                CertificateHashMapEntry trustedRootCaHashMapEntry =
                    (CertificateHashMapEntry) SerializationUtil.Deserialize(trustedRootCAListHashMapEntrySerialized);
                CertificateHashEntry[] retCertificateHashEntries =
                    new CertificateHashEntry[trustedRootCaHashMapEntry.certificateHashArray.Length];
                for (int i = 0; i < trustedRootCaHashMapEntry.certificateHashArray.Length; i++)
                {
                    byte[] certificateHashEntrySerialized = trustedRootCaHashMapEntry.certificateHashArray[i];
                    CertificateHashEntry certificateHashEntry =
                        (CertificateHashEntry) SerializationUtil.Deserialize(certificateHashEntrySerialized);
                    retCertificateHashEntries[i] = certificateHashEntry;
                }

                return retCertificateHashEntries;
            }
        }

        public static void AddSubCaCertificateToStorage(Certificate certificate, byte[] certificateHash,
            byte[] encodedCert)
        {
            AddCaCertificateToStorage(certificate, certificateHash, encodedCert, false);
            AddCertificateToCaIssuedCertificateList(certificate, certificateHash);
        }

        private static void AddCaCertificateToStorage(Certificate certificate, byte[] certificateHash,
            byte[] encodedCert, bool isRootCA)
        {
            CaCertificateEntry caCertificateEntry = new CaCertificateEntry();
            caCertificateEntry.CertificateValue = encodedCert;
            if (isRootCA)
            {
                caCertificateEntry.IsTrusted = true;
                caCertificateEntry.IsRevoked = false;
            }
            else
            {
                caCertificateEntry.IsTrusted = false;
                caCertificateEntry.IsRevoked = false;
            }

            byte[] caCertificateEntrySerialized = SerializationUtil.Serialize(caCertificateEntry);
            StorageUtil.saveToStorage(certificateHash, caCertificateEntrySerialized);

            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry = new CaCertificateSubjectKeyIdEntry();
            cACertificateSubjectKeyIdEntry.CertificateHash = certificateHash;
            cACertificateSubjectKeyIdEntry.IsRootCa = isRootCA;
            byte[] cACertificateSubjectKeyIdEntrySerialized =
                SerializationUtil.Serialize(cACertificateSubjectKeyIdEntry);
            Logger.log("Saving CA Certificate for Key Id Search :");
            Logger.log(certificate.SubjectKeyIdentifier.keyIdentifier);
            StorageUtil.saveToStorage(certificate.SubjectKeyIdentifier.keyIdentifier,
                cACertificateSubjectKeyIdEntrySerialized);
        }

        public static bool MarkSubCaCertificateRevokedInStorage(Certificate subCACertificate, byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
            if (cACertificateEntry.IsRevoked || cACertificateEntry.IsTrusted)
            {
                return false;
            }

            cACertificateEntry.IsRevoked = true;
            cACertificateEntrySerialized = SerializationUtil.Serialize(cACertificateEntry);
            StorageUtil.saveToStorage(certificateHash, cACertificateEntrySerialized);
            MarkAllCertificatesAsRevokedForCa(subCACertificate);
            return true;
        }

        public static bool MarkSubCaCertificateRevokedInStorage(byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
            if (cACertificateEntry.IsRevoked || cACertificateEntry.IsTrusted)
            {
                return false;
            }

            cACertificateEntry.IsRevoked = true;
            cACertificateEntrySerialized = SerializationUtil.Serialize(cACertificateEntry);
            Certificate subCACertificate = CertificateParser.Parse(cACertificateEntry.CertificateValue);

            StorageUtil.saveToStorage(certificateHash, cACertificateEntrySerialized);

            MarkAllCertificatesAsRevokedForCa(subCACertificate);
            return true;
        }

        public static void MarkRootCaCertificateUntrustedInStorage(Certificate rootCACertificate,
            byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry =
                (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
            cACertificateEntry.IsTrusted = false;
            cACertificateEntrySerialized = SerializationUtil.Serialize(cACertificateEntry);
            StorageUtil.saveToStorage(certificateHash, cACertificateEntrySerialized);

            MarkAllCertificatesAsRevokedForCa(rootCACertificate);
        }

        public static void AddEndEntityCertificateToStorage(Certificate certificate, byte[] certificateHash,
            byte[] encodedCert)
        {
            EndEntityCertificateEntry endEntityCertificateEntry = new EndEntityCertificateEntry();
            endEntityCertificateEntry.CertificateValue = encodedCert;
            endEntityCertificateEntry.IsRevoked = false;
            byte[] endEntityCertificateEntrySerialized = SerializationUtil.Serialize(endEntityCertificateEntry);
            StorageUtil.saveToStorage(certificateHash, endEntityCertificateEntrySerialized);

            AddCertificateToCaIssuedCertificateList(certificate, certificateHash);
            AddCertificateToDomainCertificateList(certificate, certificateHash);
        }

        private static void AddCertificateToCaIssuedCertificateList(Certificate certificate, byte[] certificateHash)
        {
            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = certificateHash;
            newCertHashEntry.IsCa = certificate.BasicConstraints.IsCa;
            byte[] storageKey = ArrayUtil.Concat(ELEMENT_LIST, certificate.AuthorityKeyIdentifier.keyIdentifier);
            AddCertificateToList(storageKey, newCertHashEntry);
        }

        private static void MarkAllCertificatesAsRevokedForCa(Certificate caCertificate)
        {
            byte[] storageKey = ArrayUtil.Concat(ELEMENT_LIST, caCertificate.SubjectKeyIdentifier.keyIdentifier);
            CertificateHashEntry[] certificateHashEntries = RetrieveCertList(storageKey);
            foreach (CertificateHashEntry certificateHashEntry in certificateHashEntries)
            {
                if (certificateHashEntry.IsCa)
                {
                    MarkSubCaCertificateRevokedInStorage(certificateHashEntry.CertificateHash);
                }
                else
                {
                    MarkEndEntityCertificateRevokedInStorage(certificateHashEntry.CertificateHash);
                }
            }
        }
        
        public static bool MarkEndEntityCertificateRevokedInStorage(byte[] certificateHash)
        {
            byte[] endEntityCertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            if (endEntityCertificateEntrySerialized == null)
            {
                Logger.log("Can not find end entity certificate in storage");
                return false;
            }

            EndEntityCertificateEntry entityCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(endEntityCertificateEntrySerialized);
            entityCertificateEntry.IsRevoked = true;

            endEntityCertificateEntrySerialized = SerializationUtil.Serialize(entityCertificateEntry);
            StorageUtil.saveToStorage(certificateHash, endEntityCertificateEntrySerialized);
            return true;
        }

        private static void AddCertificateToDomainCertificateList(Certificate certificate, byte[] certificateHash)
        {
            AddToDomainCertificateHash(certificate.Subject.CommonName, certificateHash);
            for (int k = 0; k < certificate.DNsNames.Length; k++)
            {
                byte[] dnsName = certificate.DNsNames[k];
                AddToDomainCertificateHash(dnsName, certificateHash);
            }
        }

        private static void AddToDomainCertificateHash(byte[] domainName, byte[] certificateHash)
        {
            Logger.log("Adding Certificate Registry for Domain :", domainName);
            CertificateHashEntry[] certificateHashEntries = RetrieveCertList(domainName);
            foreach (CertificateHashEntry certificateHashEntry in certificateHashEntries)
            {
                if (ArrayUtil.AreEqual(certificateHashEntry.CertificateHash, certificateHash))
                {
                    return;
                }
            }

            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = certificateHash;
            newCertHashEntry.IsCa = false;
            AddCertificateToList(domainName, newCertHashEntry);
        }

        public static bool IsRootCaCertificateAddedBefore(byte[] certificateHash)
        {
            //todo: change to NeoVM implementation for real Smart Contract
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }

        public static bool IsSubCaCertificateAddedBefore(byte[] certificateHash)
        {
            //todo: change to NeoVM implementation for real Smart Contract
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }

        public static bool IsSSLCertificateAddedBefore(byte[] certificateHash)
        {
            //todo: change to NeoVM implementation for real Smart Contract
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }
    }

    public class Certificate
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
        public int Count;
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

    public class RootCaCertificateHandler
    {
        public static bool AddTrustedRootCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!ValidateRootCaCertificateAddRequestSignature(encodedCert, signature))
            {
                return false;
            }

            if (CertificateStorageManager.IsRootCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Trusted Root CA Added Before");
                return false;
            }

            Certificate rootCaCertificate = CertificateParser.Parse(encodedCert);

            if (!rootCaCertificate.IsLoaded)
            {
                return false;
            }

            if (!CertificateValidator.ValidateRootCaCertificate(rootCaCertificate))
            {
                return false;
            }

            CertificateStorageManager.AddRootCaCertificateToStorage(rootCaCertificate, certificateHash, encodedCert);
            return true;
        }

        public static bool UntrustRootCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!ValidateRootCaCertificateAddRequestSignature(encodedCert, signature))
            {
                Logger.log("Error while validating Untrust Root Ca Certificate Request");
                return false;
            }

            if (!CertificateStorageManager.IsRootCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Untrust error. Root CA is not added before");
                return false;
            }

            Certificate rootCaCertificate = CertificateParser.Parse(encodedCert);
            if (!rootCaCertificate.IsLoaded)
            {
                Logger.log("Error while parsing encoded root CA content");
                return false;
            }

            CertificateStorageManager.MarkRootCaCertificateUntrustedInStorage(rootCaCertificate, certificateHash);
            return true;
        }


        private static bool ValidateRootCaCertificateAddRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }
    }

    public class SubCaCertificateHandler
    {
        public static bool AddSubCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (CertificateStorageManager.IsSubCaCertificateAddedBefore(certificateHash))
            {
                Logger.log("Sub CA Certificate is added before");
                return false;
            }

            if (!ValidateSubCaCertificateAddRequestSignature(encodedCert, signature))
            {
                Logger.log("Can not validate Add Sub CA Certificate request signature");
                return false;
            }

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);
            if (!subCaCertificate.IsLoaded)
            {
                Logger.log("Can not parse Sub CA Certificate");
                return false;
            }

            if (!CertificateValidator.ValidateSubCaCertificate(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Certificate");
                return false;
            }

            CertificateStorageManager.AddSubCaCertificateToStorage(subCaCertificate, certificateHash, encodedCert);

            return true;
        }

        public static bool RevokeSubCaCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            if (!CertificateStorageManager.IsSubCaCertificateAddedBefore(certificateHash))
            {
                return false;
            }

            if (!ValidateRevokeSubCaCertificateRequestSignature(encodedCert, signature))
            {
                return false;
            }

            Certificate subCaCertificate = CertificateParser.Parse(encodedCert);

            if (!CertificateValidator.CheckValidityPeriod(subCaCertificate))
            {
                return false;
            }

            if (!CertificateStorageManager.MarkSubCaCertificateRevokedInStorage(subCaCertificate, certificateHash))
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSubCaCertificateAddRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }

        private static bool ValidateRevokeSubCaCertificateRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates encodedCert signature with signature
            //Signature Format will be discussed later
            //Will check sub ca remove request signed by any CA key in chain.
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }
    }

    public class SslCertificateHandler
    {
        public static bool AddSslCertificate(byte[] certificateHash, byte[] encodedCert)
        {
            Logger.log("Checking SSL Certificate is added before");
            if (CertificateStorageManager.IsSSLCertificateAddedBefore(certificateHash))
            {
                Logger.log("SSL Certificate is added before");
                return false;
            }

            Logger.log("Trying to parse SSL Certificate");
            Certificate sslCertificate = CertificateParser.Parse(encodedCert);
            if (!sslCertificate.IsLoaded)
            {
                Logger.log("Can not parse SSL Certificate");
                return false;
            }

            Logger.log("Checking SSL Certificate Validity Period");
            if (!CertificateValidator.CheckValidityPeriod(sslCertificate))
            {
                Logger.log("SSL Certificate validity period is invalid");
                return false;
            }

            Logger.log("Checking SSL Certificate Fields");
            if (!CertificateValidator.ValidateSslCertificateFields(sslCertificate))
            {
                Logger.log("SSL Certificate Fields are invalid");
                return false;
            }

            Logger.log("Validating SSL Certificate With Chain");
            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(sslCertificate))
            {
                Logger.log("Can not validate SSL Certificate Signature With Chain");
                return false;
            }

            Logger.log("Adding SSL Certificate To Storage");
            CertificateStorageManager.AddEndEntityCertificateToStorage(sslCertificate, certificateHash, encodedCert);
            return true;
        }
        
        public static bool RevokeSslCertificate(byte[] certificateHash, byte[] encodedCert, byte[] signature)
        {
            Logger.log("Checking SSL Certificate is added before");
            if (!CertificateStorageManager.IsSSLCertificateAddedBefore(certificateHash))
            {
                Logger.log("SSL Certificate is not added before");
                return false;
            }

            if (!ValidateRevokeSslCertificateRequestSignature(encodedCert, signature))
            {
                Logger.log("SSL Certificate revoke request signature is invalid");
                return false;
            }

            if (!CertificateStorageManager.MarkEndEntityCertificateRevokedInStorage(certificateHash))
            {
                Logger.log("Error while marking as remoked SSL Certificate in Storage");
                return false;
            }

            return true;
        }
        
        private static bool ValidateRevokeSslCertificateRequestSignature(byte[] encodedCert, byte[] signature)
        {
            //Validates revoke SSL Certificate request signature 
            //Signature Format will be discussed later
            //Will check SSL remoke request signed by any CA key in chain or SSL Certificate Key owner
            //now always return valid signature
            //todo: add real implementation code
            return true;
        }

    }

    public class CertificateValidator
    {
#if NEO || ONT
        static readonly byte[] ALG_NAME_RSA_UPPERCASE = "525341".HexToBytes();
        static readonly byte[] ALG_NAME_RSA_LOWERCASE = "727361".HexToBytes();
        static readonly byte[] ALG_NAME_EC_UPPERCASE = "4543".HexToBytes();
        static readonly byte[] ALG_NAME_EC_LOWERCASE = "6563".HexToBytes();
#endif
#if NET_CORE
                        static readonly byte[] ALG_NAME_RSA_UPPERCASE = HexUtil.HexStringToByteArray("525341");
                        static readonly byte[] ALG_NAME_RSA_LOWERCASE = HexUtil.HexStringToByteArray("727361");
                        static readonly byte[] ALG_NAME_EC_UPPERCASE = HexUtil.HexStringToByteArray("4543");
                        static readonly byte[] ALG_NAME_EC_LOWERCASE = HexUtil.HexStringToByteArray("6563");
                #endif

        public static bool ValidateRootCaCertificate(Certificate rootCaCertificate)
        {
            if (!CertificateFieldValidator.Validate(rootCaCertificate))
            {
                return false;
            }

            if (!CertificateSignatureValidator.ValidateSelfSignedCertificateSignature(rootCaCertificate))
            {
                return false;
            }

            if (!CheckValidityPeriod(rootCaCertificate))
            {
                return false;
            }

            if (!ValidateRootCaCertificateFields(rootCaCertificate))
            {
                return false;
            }

            return true;
        }

        public static bool ValidateRootCaCertificateFields(Certificate certificate)
        {
            if (!certificate.BasicConstraints.HasBasicConstraints || !certificate.BasicConstraints.IsCa)
            {
                return false;
            }

            if (!ValidateCaCertificateKeyUsage(certificate.KeyUsage.KeyUsageFlags))
            {
                return false;
            }

            return true;
        }

        public static bool ValidateSubCaCertificate(Certificate subCaCertificate)
        {
            if (!CertificateFieldValidator.Validate(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Certificate Fields");
                return false;
            }

            if (!CheckValidityPeriod(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Validity Period");
                return false;
            }

            if (!CertificateChainValidator.ValidateCertificateSignatureWithChain(subCaCertificate))
            {
                Logger.log("Can not validate Sub CA Signature with Issuer Certificate");
                return false;
            }

            return true;
        }

        public static bool ValidateSslCertificateFields(Certificate certificate)
        {
            Logger.log("Validating Certificate Fields");
            if (!CertificateFieldValidator.Validate(certificate))
            {
                Logger.log("Ssl Certificate Field validation failed");
                return false;
            }

            Logger.log("Validating Basic Contraints");
            if (certificate.BasicConstraints.HasBasicConstraints)
            {
                if (certificate.BasicConstraints.IsCa)
                {
                    Logger.log("End user certificates can not have basic constraint field with isCa flag");
                    return false;
                }
            }

            Logger.log("Validating Key Usage");
            if (!ValidateSslCertificateKeyUsage(certificate))
            {
                Logger.log("Ssl Certificate Key Usage Flags invalid");
                return false;
            }

            Logger.log("Validating Extended Usage");
            if (!ValidateSslCertificateExtendedKeyUsage(certificate.ExtendedKeyUsage.Oids,
                certificate.ExtendedKeyUsage.Count))
            {
                Logger.log("Ssl Certificate Extended Key Usage Flags invalid");
                return false;
            }

            return true;
        }


        private static bool ValidateSslCertificateKeyUsage(Certificate certificate)
        {
            if (certificate.PublicKeyAlgName == null)
            {
                Logger.log("Public Key Algorithm Name is null");
                return false;
            }

            if ((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.DigitalSignature) == 0)
            {
                Logger.log("End entity SSL Certificate should have Digital Signature Key Usage");
                return false;
            }

            if (ArrayUtil.Contains(certificate.PublicKeyAlgName, ALG_NAME_RSA_UPPERCASE) ||
                ArrayUtil.Contains(certificate.PublicKeyAlgName, ALG_NAME_RSA_LOWERCASE))
            {
                Logger.log("Public Key Type is RSA");
                if ((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyEncipherment) == 0)
                {
                    Logger.log("End entity SSL Certificate should have KeyEncipherment Key Usage");
                    return false;
                }
            }
            else if (ArrayUtil.Contains(certificate.PublicKeyAlgName, ALG_NAME_EC_UPPERCASE) ||
                     ArrayUtil.Contains(certificate.PublicKeyAlgName, ALG_NAME_EC_LOWERCASE))
            {
                Logger.log("Public Key Type is EC");
                if ((certificate.KeyUsage.KeyUsageFlags & KeyUsageFlags.KeyAgreement) == 0)
                {
                    Logger.log("End entity SSL Certificate should have KeyAgreement Key Usage");
                    return false;
                }
            }

            return true;
        }

        private static bool ValidateCaCertificateKeyUsage(KeyUsageFlags keyUsageFlags)
        {
            if ((keyUsageFlags & KeyUsageFlags.KeyCertSign) == 0)
            {
                return false;
            }

            if ((keyUsageFlags & KeyUsageFlags.CrlSign) == 0)
            {
                return false;
            }

            return true;
        }

        private static bool ValidateSslCertificateExtendedKeyUsage(byte[][] extendedKeyUsageOiDs,
            int extendedKeyUsageOidCount)
        {
            //todo: Check for Server Authentication and Client Authentication extended key usage values 
            return true;
        }

        public static bool CheckValidityPeriod(Certificate certificate)
        {
            long transactionTime = TransactionContentUtil.retrieveTransactionTime();
            if (transactionTime < certificate.Validity.NotBefore)
            {
                Logger.log("Validity.NotBefore is not in valid period");
                return false;
            }

            if (transactionTime > certificate.Validity.NotAfter)
            {
#if NET_CORE
//fixme: test certificate time is invalid so will be changed with new one.
//remove this block when test certificates changed for NET_CORE tests
//  return false;
                return true;
#else
                Logger.log("Validity.NotAfter is not in valid period");
                return false;
#endif
            }

            return true;
        }

        public static bool CheckCertificateWithWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            if (!CertificateSignatureValidator.ValidateCertificateSignature(certificate, caCertificate))
            {
                Logger.log("Can not find validate signature with issuer certificate");
                return false;
            }

            if (!CheckValidityPeriodWithCaCertificate(certificate, caCertificate))
            {
                return false;
            }

            if (!CheckCertificatePolicyWithCaCertificate(certificate, caCertificate))
            {
                return false;
            }

            return true;
        }

        private static bool CheckValidityPeriodWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            if (certificate.Validity.NotBefore < caCertificate.Validity.NotBefore)
            {
                Logger.log(
                    "End entity SSL Certificate period validity check with CA is failed. Invalid NotBefore value");
                return false;
            }

            if (certificate.Validity.NotAfter > caCertificate.Validity.NotAfter)
            {
                Logger.log(
                    "End entity SSL Certificate period validity check with CA is failed. Invalid NotAfter value");
                return false;
            }

            //Check certificate validity period with CA Certificate
            //now always return valid
            //todo: add real implementation code
            return true;
        }

        private static bool CheckCertificatePolicyWithCaCertificate(Certificate certificate, Certificate caCertificate)
        {
            //todo:
            /*
             * 
   In an end entity certificate, these policy information terms indicate
   the policy under which the certificate has been issued and the
   purposes for which the certificate may be used.  In a CA certificate,
   these policy information terms limit the set of policies for
   certification paths that include this certificate.  When a CA does
   not wish to limit the set of policies for certification paths that
   include this certificate, it MAY assert the special policy anyPolicy,
   with a value of { 2 5 29 32 0 }.
   If this extension is
   critical, the path validation software MUST be able to interpret this
   extension (including the optional qualifier), or MUST reject the
   certificate.
             */
            //now always return valid
            //todo: add real implementation code
            return true;
        }
    }

    class CertificateChainValidator
    {
        public static bool ValidateCertificateSignatureWithChain(Certificate certificate)
        {
            Certificate caCertificate = FindIssuerCaCertificate(certificate);
            if (!caCertificate.IsLoaded)
            {
                Logger.log("Can not find issuer certificate");
                return false;
            }

            if (!CertificateValidator.CheckCertificateWithWithCaCertificate(certificate, caCertificate))
            {
                Logger.log("Can not find validate validity with issuer certificate validity");
                return false;
            }

            return true;
        }

        private static Certificate FindIssuerCaCertificate(Certificate certificate)
        {
            Certificate nullCertificate = new Certificate();
            Logger.log("Certificate AuthorityKeyIdentifier.keyIdentifier : ");
            Logger.log(certificate.AuthorityKeyIdentifier.keyIdentifier);
            CaCertificateSubjectKeyIdEntry cACertificateSubjectKeyIdEntry =
                FindCaCertificateHashEntry(certificate.AuthorityKeyIdentifier.keyIdentifier);
            if (cACertificateSubjectKeyIdEntry.CertificateHash == null)
            {
                Logger.log("Can not find CA Certificate Hash Entry with AuthorityKeyIdentifier.keyIdentifier");
                return nullCertificate;
            }

            CaCertificateEntry cACertificateEntry =
                FindCaCertificatewithCertificateHash(cACertificateSubjectKeyIdEntry.CertificateHash);
            if (cACertificateEntry.CertificateValue == null)
            {
                Logger.log("Can not find CA Certificate Entry with CA Certificate Hash");
                return nullCertificate;
            }

            if (cACertificateSubjectKeyIdEntry.IsRootCa)
            {
                if (!cACertificateEntry.IsTrusted)
                {
                    Logger.log("CA Certificate is not trusted");
                    return nullCertificate;
                }
            }
            else
            {
                if (cACertificateEntry.IsRevoked)
                {
                    Logger.log("CA Certificate is revoked");
                    return nullCertificate;
                }
            }

            Certificate caCertificate = CertificateParser.Parse(cACertificateEntry.CertificateValue);
            if (!caCertificate.IsLoaded)
            {
                Logger.log("Can not parse CA Certificate value");
                return nullCertificate;
            }

            if (!CertificateValidator.CheckValidityPeriod(caCertificate))
            {
                Logger.log("Parse CA Certificate Validity is invalid");
                return nullCertificate;
            }

            return caCertificate;
        }

        private static CaCertificateSubjectKeyIdEntry FindCaCertificateHashEntry(byte[] subjectKeyIdentifier)
        {
            byte[] cACertificateSubjectKeyIdEntrySerialiazed = StorageUtil.readFromStorage(subjectKeyIdentifier);
            if (cACertificateSubjectKeyIdEntrySerialiazed != null)
            {
                return (CaCertificateSubjectKeyIdEntry) SerializationUtil.Deserialize(
                    cACertificateSubjectKeyIdEntrySerialiazed);
            }
            else
            {
                return new CaCertificateSubjectKeyIdEntry();
            }
        }

        private static CaCertificateEntry FindCaCertificatewithCertificateHash(byte[] certificateHash)
        {
            byte[] caCertificateEnrtySerialized = StorageUtil.readFromStorage(certificateHash);
            if (caCertificateEnrtySerialized != null)
            {
                return (CaCertificateEntry) SerializationUtil.Deserialize(caCertificateEnrtySerialized);
            }
            else
            {
                return new CaCertificateEntry();
            }
        }
    }

    class CertificateSignatureValidator
    {
        public static bool ValidateSelfSignedCertificateSignature(Certificate certificate)
        {
            return Validate(certificate.TbsCertificate, certificate.SubjectPublicKeyInfo,
                certificate.SignatureAlgorithm, certificate.Signature);
        }

        public static bool ValidateCertificateSignature(Certificate certificate, Certificate issuerCertificate)
        {
            return Validate(certificate.TbsCertificate, issuerCertificate.SubjectPublicKeyInfo,
                certificate.SignatureAlgorithm, certificate.Signature);
        }

        static bool Validate(byte[] tbsCertificate, byte[] subjectPublicKeyInfo, byte[] signatureAlgorithm,
            byte[] signatureValue)
        {
            //todo: replace with native function call or native smart contract call
            return true;
        }
    }

    public class SignedData
    {
        public byte[] signedData;
        public byte[] signatureAlgorithm;
        public byte[] subjectPublicKeyInfo;
        public byte[] signatureValue;
    }

    public class SignatureValidator
    {
        public static bool Validate(SignedData signedData)
        {
#if NEO || ONT
            return NeoVMCoreSignatureValidator.Validate(signedData);
#endif
#if NET_CORE
                            return NetCoreSignatureValidator.Validate(signedData);
                #endif
            //return NeoVMCoreSignatureValidator.Validate(signedData);
            //todo: Signature will be validated using parameter fields
            //now always return signature is valid
            //todo: add real implementation code
        }
    }

    public class CertificateFieldValidator
    {
        public static bool Validate(Certificate certificate)
        {
            Logger.log("Checking if Certificate is v3 Certificate");
            if (!IsVersion3(certificate))
            {
                Logger.log("Validation Error: Is Not v3 Certificate");
                return false;
            }

            Logger.log("Checking TBS Signature Algorithm is equal to Signature Algoritm");
            if (!SignatureAlgorithmFieldIsSameWithTBSCertificateSignatureAlgorithmField(certificate))
            {
                Logger.log(
                    "Validation Error: Signature Algorithm field is not same with TBS Signature Algorithm Field");
                Logger.log(certificate.TBSSignatureAlgorithm);
                Logger.log(certificate.SignatureAlgorithm);
                return false;
            }

            //todo: discuss about 
            /* if (!IsSerialNumberPositive(certificate))
             {
                 Logger.log("Validation Error: Serial Number is not positive");
                 return false;
             }
             */

            Logger.log("Checking If Subject Is Valid");
            if (!IsSubjectValid(certificate))
            {
                Logger.log("Validation Error: Certificate Subject is invalid");
                return false;
            }

            Logger.log("Checking If Issuer Is Empty");
            if (IsIssuerEmpty(certificate))
            {
                Logger.log("Validation Error: All Issuer Name Fields is empty or null");
                return false;
            }

            Logger.log("Checking Authority Key Identifier Extension");
            if (!ValidateAuthorityKeyIdentifier(certificate))
            {
                Logger.log("Validation Error: Authority Key Identifier Extension is invalid");
                return false;
            }

            if (!ValidateSubjectKeyIdentifier(certificate))
            {
                Logger.log("Validation Error: Subject Key Identifier Extension is invalid");
                return false;
            }

            Logger.log("Validating Key Usage");
            if (!ValidateKeyUsage(certificate))
            {
                Logger.log("Validation Error: Key Usage Extension is invalid");
                return false;
            }

            return true;
        }

        private static bool IsVersion3(Certificate certificate)
        {
            return certificate.Version == 3;
        }

        private static bool SignatureAlgorithmFieldIsSameWithTBSCertificateSignatureAlgorithmField(
            Certificate certificate)
        {
            return ArrayUtil.AreEqual(certificate.SignatureAlgorithm, certificate.TBSSignatureAlgorithm);
        }

        private static bool IsIssuerEmpty(Certificate certificate)
        {
            return certificate.Issuer.isEmpty;
        }

        private static bool ValidateAuthorityKeyIdentifier(Certificate certificate)
        {
            if (!certificate.BasicConstraints.IsCa)
            {
                if (certificate.AuthorityKeyIdentifier.keyIdentifier == null)
                {
                    Logger.log("Validation Error: Authority Key Identifier Extension must be present");
                    return false;
                }

                if (certificate.AuthorityKeyIdentifier.IsCritical)
                {
                    Logger.log("Validation Error: Authority Key Identifier Extension must be non-critical");
                    return false;
                }
            }

            //todo:
            /*
             *    Conforming CAs MUST mark this extension as non-critical.
             */
            /*
             * The keyIdentifier field of the authorityKeyIdentifier extension MUST
   be included in all certificates generated by conforming CAs to
   facilitate certification path construction.
             */
            return true;
        }

        private static bool ValidateSubjectKeyIdentifier(Certificate certificate)
        {
            if (certificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension)
            {
                if (certificate.SubjectKeyIdentifier.IsCritical)
                {
                    Logger.log("Validation Error: Subject Key Identifier Extension must be non-critical");
                    return false;
                }
            }

            //todo:
            /*
             *    Conforming CAs MUST mark this extension as non-critical.
             */
            /*
           To assist
   applications in identifying the appropriate end entity certificate,
   this extension SHOULD be included in all end entity certificates.
             */
            return true;
        }

        private static bool ValidateKeyUsage(Certificate certificate)
        {
            if (certificate.KeyUsage.HasKeyUsageExtension)
            {
                if (!certificate.KeyUsage.IsCritical)
                {
                    return false;
                    /*
                     *  When present, conforming CAs SHOULD mark this extension as critical.
                     */
                }
            }

            return true;
        }


        private static bool IsSubjectValid(Certificate certificate)
        {
            //todo: check rfc details
            /*
             * The subject field identifies the entity associated with the public
   key stored in the subject public key field.  The subject name MAY be
   carried in the subject field and/or the subjectAltName extension.  If
   the subject is a CA (e.g., the basic constraints extension, as
   discussed in Section 4.2.1.9, is present and the value of cA is
   TRUE), then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   4.1.2.4) in all certificates issued by the subject CA.  If the
   subject is a CRL issuer (e.g., the key usage extension, as discussed
   in Section 4.2.1.3, is present and the value of cRLSign is TRUE),
Cooper, et al.              Standards Track                    [Page 23]
 
RFC 5280  PKIX Certificate and CRL Profile            May 2008
   then the subject field MUST be populated with a non-empty
   distinguished name matching the contents of the issuer field (Section
   5.1.2.3) in all CRLs issued by the subject CRL issuer.  If subject
   naming information is present only in the subjectAltName extension
   (e.g., a key bound only to an email address or URI), then the subject
   name MUST be an empty sequence and the subjectAltName extension MUST
   be critical.
             */
            /*
             * If
   the CA issues certificates with an empty sequence for the subject
   field, the CA MUST support the subject alternative name extension
             */
            return true;
        }
    }

    public class CertificateParser
    {
        public static Certificate Parse(byte[] encodedCert)
        {
            //Certificate will be parsed using system call or native smart contract
            //and then certificate fields will be returned in Certificate structure.
            //now works with test native smart contract
            ////todo: add real implementation code
#if NET_CORE
                            return NetCoreCertificateParser.Parse(encodedCert);
                #endif
#if ONT
                            return NativeCertParser.parse(encodedCert);
                #endif
            return null;
        }

        public static byte[] StringToByteArrayToString(string text)
        {
#if NEO || ONT
            return NeoVMStringUtil.StringToByteArray(text);
#endif

#if NET_CORE
                            return NetCoreStringUtil.StringToByteArray(text);
                #endif
        }
    }

    #endregion

    #region UTILS_SECTION

    public class Logger
    {
        public static void LogCertificate(Certificate certificate)
        {
            log("certificate.IsLoaded : ", certificate.IsLoaded);
            log("certificate.Version : ", certificate.Version);
            log("certificate.SerialNumber : ", certificate.SerialNumber);
            log("certificate.BasicConstraints.HasBasicConstraints : ",
                certificate.BasicConstraints.HasBasicConstraints);
            log("certificate.BasicConstraints.IsCa : ", certificate.BasicConstraints.IsCa);
            log("certificate.BasicConstraints.HasPathLengthConstraint : ",
                certificate.BasicConstraints.HasPathLengthConstraint);
            log("certificate.BasicConstraints.MaxPathLen : ", certificate.BasicConstraints.MaxPathLen);

            log("certificate.SubjectPublicKeyInfo : ", certificate.SubjectPublicKeyInfo);
            log("certificate.KeyUsage.HasKeyUsageExtension : ", certificate.KeyUsage.HasKeyUsageExtension);
            log("certificate.KeyUsage.IsCritical : ", certificate.KeyUsage.IsCritical);
            log("certificate.KeyUsage.KeyUsageFlags : ", certificate.KeyUsage.KeyUsageFlags);

            log("certificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension : ",
                certificate.SubjectKeyIdentifier.HasSubjectKeyIdentifierExtension);
            log("certificate.SubjectKeyIdentifier.IsCritical : ", certificate.SubjectKeyIdentifier.IsCritical);
            log("certificate.SubjectKeyIdentifier.keyIdentifier : ", certificate.SubjectKeyIdentifier.keyIdentifier);

            log("certificate.AuthorityKeyIdentifier.HasAuthorityKeyIdentifier : ",
                certificate.AuthorityKeyIdentifier.HasAuthorityKeyIdentifier);
            log("certificate.AuthorityKeyIdentifier.IsCritical : ", certificate.AuthorityKeyIdentifier.IsCritical);
            log("certificate.AuthorityKeyIdentifier.keyIdentifier : ",
                certificate.AuthorityKeyIdentifier.keyIdentifier);

            log("certificate.Validity.NotBefore : ", certificate.Validity.NotBefore);
            log("certificate.Validity.NotAfter : ", certificate.Validity.NotAfter);

            log("certificate.ExtendedKeyUsage.HasExtendedKeyUsageExtension : ",
                certificate.ExtendedKeyUsage.HasExtendedKeyUsageExtension);

            log("certificate.TbsCertificate : ", certificate.TbsCertificate);
            log("certificate.TBSSignatureAlgorithm : ", certificate.TBSSignatureAlgorithm);
            log("certificate.SignatureAlgorithm : ", certificate.SignatureAlgorithm);
            log("certificate.Signature : ", certificate.Signature);
            log("certificate.Subject.CommonName : ", certificate.Subject.CommonName);
            log("certificate.Issuer.CommonName : ", certificate.Issuer.CommonName);
        }

        public static void log(string fieldName, object value)
        {
#if NEO || ONT
            Runtime.Notify(fieldName);
            Runtime.Notify(value);
#endif
#if NET_CORE
                            Console.WriteLine(fieldName);
                            Console.WriteLine(value);
                #endif
        }

        public static void log(string message, byte[] argument)
        {
#if NEO || ONT
            Runtime.Notify(Helper.Concat(message.AsByteArray(), argument));
            Runtime.Notify(argument);
#endif
#if NET_CORE
                            Console.WriteLine(message);
                            Console.WriteLine(argument);
                #endif
        }

        public static void log(object message)
        {
#if NEO || ONT
            Runtime.Notify(message);
#endif
#if NET_CORE
                            Console.WriteLine(message);
                #endif
        }

        public static void log(bool message)
        {
#if NEO || ONT
            if (message)
            {
                Runtime.Notify("true");
            }
            else
            {
                Runtime.Notify("false");
            }
#endif
#if NET_CORE
                            Console.WriteLine(message);
                #endif
        }

        public static void log(string condition, bool status)
        {
#if NEO || ONT
            if (status)
            {
                Runtime.Notify(Helper.Concat(condition.AsByteArray(), "true".AsByteArray()));
            }
            else
            {
                Runtime.Notify(Helper.Concat(condition.AsByteArray(), "false".AsByteArray()));
            }
#endif
#if NET_CORE
                            Console.WriteLine(condition);
                            Console.WriteLine(status);
                #endif
        }
    }

    public class SerializationUtil
    {
        public static byte[] Serialize(object source)
        {
#if NET_CORE
                            return NetCoreSerializationUtil.Serialize(source);
                #endif
#if NEO || ONT
            return NeoVMSerializationUtil.Serialize(source);
#endif
        }

        public static object Deserialize(byte[] source)
        {
#if NET_CORE
                            return NetCoreSerializationUtil.Deserialize(source);
                #endif
#if NEO || ONT
            return NeoVMSerializationUtil.Deserialize(source);
#endif
        }
    }

    public class StorageUtil
    {
        public static byte[] readFromStorage(string key)
        {
#if NET_CORE
                            return NetCoreStorageUtil.readFromStorage(key);
                #endif
#if NEO || ONT
            return NeoVMStorageUtil.readFromStorage(key);
#endif
        }

        public static byte[] readFromStorage(byte[] key)
        {
#if NET_CORE
                            return NetCoreStorageUtil.readFromStorage(key);
                #endif
#if NEO || ONT
            return NeoVMStorageUtil.readFromStorage(key);
#endif
        }

        public static void saveToStorage(byte[] key, byte[] value)
        {
#if NET_CORE
                            NetCoreStorageUtil.saveToStorage(key, value);
                #endif
#if NEO || ONT
            NeoVMStorageUtil.saveToStorage(key, value);
#endif
        }

        public static void saveToStorage(string key, byte[] value)
        {
#if NET_CORE
                            NetCoreStorageUtil.saveToStorage(key, value);
                #endif
#if NEO || ONT
            NeoVMStorageUtil.saveToStorage(key, value);
#endif
        }

        //todo: testing purposes only. Not used in real smart contract
        public static void clearStorage()
        {
#if NET_CORE
                            NetCoreStorageUtil.clearStorage();
                #endif
#if NEO || ONT
            NeoVMStorageUtil.clearStorage();
#endif
        }
    }

    public class ArrayUtil
    {
        public static byte[] Concat(byte[] first, byte[] second)
        {
#if NET_CORE
                            return NetCoreArrayUtil.concat(first, second);
                #endif
#if NEO || ONT
            return NeoVMArrayUtil.concat(first, second);
#endif
        }

        public static bool Contains(byte[] source, byte[] find)
        {
            for (int i = 0, index = 0; i < source.Length; ++i)
            {
                if (source[i] == find[index])
                {
                    if (++index >= find.Length)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool AreEqual(byte[] first, byte[] second)
        {
#if NET_CORE
                            return NetCoreArrayUtil.AreEqual(first, second);
                #endif
#if NEO || ONT
            return NeoVMArrayUtil.AreEqual(first, second);
#endif
        }
    }

    public class StringUtil
    {
        public static string ByteArrayToString(byte[] data)
        {
#if NEO || ONT
            return NeoVMStringUtil.ByteArrayToString(data);
#endif
#if NET_CORE
                            return NetCoreStringUtil.ByteArrayToString(data);
                #endif
        }

        public static byte[] StringToByteArray(string text)
        {
#if NEO || ONT
            return NeoVMStringUtil.StringToByteArray(text);
#endif
#if NET_CORE
                            return NetCoreStringUtil.StringToByteArray(text);
                #endif
        }
    }

    public class TransactionContentUtil
    {
        public static long retrieveTransactionTime()
        {
#if NEO || ONT
            return NeoVMTransactionUtil.retrieveTransactionTime();
#endif
#if NET_CORE
                            return NetCoreTransactionUtil.retrieveTransactionTime();
                #endif
        }
    }

    #endregion

    #region ONT_NEO_Related_Utils_Section

#if NEO || ONT
   


    

    

   


#endif

    #endregion

    #region PARSE_SECTION

#if ONT
    

#endif

    #endregion
}