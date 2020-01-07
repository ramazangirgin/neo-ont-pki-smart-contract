using System;
using System.Collections.Generic;
using CertLedgerBusinessSCTemplate.io.certledger.smartcontract.business;
using io.certledger.smartcontract.business.util;

namespace io.certledger.smartcontract.business
{
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
         //todo: change with Neo MAP
        //public Dictionary<int, CertificateHashEntry> CertificateHashMap;
        public List<CertificateHashEntry> CertificateHashList;
        //public int Count;
    }

    public class CertificateStorageManager
    {
        public static string TRUSTED_ROOT_CA_LIST_STORAGE_KEY = "TRUSTED_ROOT_CA_LIST_STORAGE_KEY";
        public static byte[] KEY_ID = StringUtil.StringToByteArray("KEY_ID_");
        public static byte[] ELEMENT_LIST = StringUtil.StringToByteArray("ELEMENT_LIST_");


        public static void AddRootCaCertificateToStorage(Certificate certificate, byte[] certificateHash, byte[] encodedCert)
        {
            AddCaCertificateToStorage(certificate, certificateHash, encodedCert, true);
            AddRootCaCertificateToRootCaList(certificateHash); //Discuss trusted root CA list
        }

        private static void AddRootCaCertificateToRootCaList(byte[] rootCACertificateHash)
        {
            CertificateHashMapEntry trustedRootCaHashMapEntry;
            byte[] trustedRootCAListHashMapEntrySerialized = StorageUtil.readFromStorage(TRUSTED_ROOT_CA_LIST_STORAGE_KEY);
            if (trustedRootCAListHashMapEntrySerialized == null)
            {
                trustedRootCaHashMapEntry = new CertificateHashMapEntry();
                trustedRootCaHashMapEntry.CertificateHashList = new List<CertificateHashEntry>();
                //trustedRootCaHashMapEntry.Count = 0;
            }
            else
            {
                trustedRootCaHashMapEntry = (CertificateHashMapEntry) SerializationUtil.Deserialize(trustedRootCAListHashMapEntrySerialized);
            }

            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = rootCACertificateHash;
            newCertHashEntry.IsCa = true;
            trustedRootCaHashMapEntry.CertificateHashList.Add(newCertHashEntry);
            //trustedRootCaHashMapEntry.Count += 1;

            trustedRootCAListHashMapEntrySerialized = SerializationUtil.Serialize(trustedRootCaHashMapEntry);
            StorageUtil.saveToStorage(TRUSTED_ROOT_CA_LIST_STORAGE_KEY, trustedRootCAListHashMapEntrySerialized);
        }

        public static void AddSubCaCertificateToStorage(Certificate certificate, byte[] certificateHash, byte[] encodedCert)
        {
            AddCaCertificateToStorage(certificate, certificateHash, encodedCert, false);
        }

        private static void AddCaCertificateToStorage(Certificate certificate, byte[] certificateHash, byte[] encodedCert, bool isRootCA)
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
            byte[] cACertificateSubjectKeyIdEntrySerialized = SerializationUtil.Serialize(cACertificateSubjectKeyIdEntry);
            StorageUtil.saveToStorage(certificate.SubjectKeyIdentifier.keyIdentifier, cACertificateSubjectKeyIdEntrySerialized);
        }

        public static bool MarkSubCaCertificateRevokedInStore(Certificate subCACertificate, byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
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

        public static bool MarkSubCaCertificateRevokedInStore(byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
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

        public static void MarkRootCaCertificateUntrustedInStorage(Certificate rootCACertificate, byte[] certificateHash)
        {
            byte[] cACertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            CaCertificateEntry cACertificateEntry = (CaCertificateEntry) SerializationUtil.Deserialize(cACertificateEntrySerialized);
            cACertificateEntry.IsTrusted = false;
            cACertificateEntrySerialized = SerializationUtil.Serialize(cACertificateEntry);
            StorageUtil.saveToStorage(certificateHash, cACertificateEntrySerialized);

            MarkAllCertificatesAsRevokedForCa(rootCACertificate);
        }

        public static void AddEndEntityCertificateToStorage(Certificate certificate, byte[] certificateHash, byte[] encodedCert)
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
            CertificateHashMapEntry certHashMapEntry;
            byte[] storageKey = ArrayUtil.Concat(ELEMENT_LIST, certificate.AuthorityKeyIdentifier.keyIdentifier);
            byte[] certHashMapEntrySerialized = StorageUtil.readFromStorage(storageKey);
            if (certHashMapEntrySerialized == null)
            {
                certHashMapEntry = new CertificateHashMapEntry();
                certHashMapEntry.CertificateHashList = new List<CertificateHashEntry>();
                //certHashMapEntry.Count = 0;
            }
            else
            {
                certHashMapEntry = (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
            }

            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = certificateHash;
            newCertHashEntry.IsCa = certificate.BasicConstraints.IsCa;
            certHashMapEntry.CertificateHashList.Add(newCertHashEntry);
//            certHashMapEntry.Count += 1;

            certHashMapEntrySerialized = SerializationUtil.Serialize(certHashMapEntry);
            StorageUtil.saveToStorage(storageKey, certHashMapEntrySerialized);
        }

        private static void MarkAllCertificatesAsRevokedForCa(Certificate caCertificate)
        {
            byte[] storageKey = ArrayUtil.Concat(ELEMENT_LIST, caCertificate.SubjectKeyIdentifier.keyIdentifier);
            byte[] certHashMapEntrySerialized = StorageUtil.readFromStorage(storageKey);

            if (certHashMapEntrySerialized == null)
            {
                return;
            }

            CertificateHashMapEntry certHashMapEntry = (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
            foreach (var certificateHashEntry in certHashMapEntry.CertificateHashList)
            {
                if (certificateHashEntry.IsCa)
                {
                    MarkSubCaCertificateRevokedInStore(certificateHashEntry.CertificateHash);
                }
                else
                {
                    MarkEndEntityCertificateRevokedInStore(certificateHashEntry.CertificateHash);
                }
            }
        }

        private static void MarkEndEntityCertificateRevokedInStore(byte[] certificateHash)
        {
            byte[] endEntityCertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            if (endEntityCertificateEntrySerialized == null)
            {
                return;
            }

            EndEntityCertificateEntry entityCertificateEntry = (EndEntityCertificateEntry) SerializationUtil.Deserialize(endEntityCertificateEntrySerialized);
            entityCertificateEntry.IsRevoked = true;

            endEntityCertificateEntrySerialized = SerializationUtil.Serialize(entityCertificateEntry);
            StorageUtil.saveToStorage(certificateHash, endEntityCertificateEntrySerialized);
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
            CertificateHashMapEntry certHashMapEntry;
            byte[] certHashMapEntrySerialized = StorageUtil.readFromStorage(domainName);
            if (certHashMapEntrySerialized == null)
            {
                certHashMapEntry = new CertificateHashMapEntry();
                certHashMapEntry.CertificateHashList = new List<CertificateHashEntry>();
            }
            else
            {
                certHashMapEntry = (CertificateHashMapEntry) SerializationUtil.Deserialize(certHashMapEntrySerialized);
            }

            foreach (var certificateHashEntry in certHashMapEntry.CertificateHashList)
            {
                if (ArrayUtil.AreEqual(certificateHashEntry.CertificateHash, certificateHash))
                {
                    return;
                }
            }

            CertificateHashEntry newCertHashEntry = new CertificateHashEntry();
            newCertHashEntry.CertificateHash = certificateHash;
            newCertHashEntry.IsCa = false;
            certHashMapEntry.CertificateHashList.Add(newCertHashEntry);
            //certHashMapEntry.Count += 1;

            certHashMapEntrySerialized = SerializationUtil.Serialize(certHashMapEntry);

            StorageUtil.saveToStorage(domainName, certHashMapEntrySerialized);
        }

        public static bool IsRootCaCertificateAddedBefore(byte[] certificateHash)
        {
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }

        public static bool IsSubCaCertificateAddedBefore(byte[] certificateHash)
        {
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }

        public static bool IsSSLCertificateAddedBefore(byte[] certificateHash)
        {
            byte[] value = StorageUtil.readFromStorage(certificateHash);
            return (value != null);
        }
    }
}