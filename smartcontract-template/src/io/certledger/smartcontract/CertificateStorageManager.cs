using System;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
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
        
        public static EndEntityCertificateEntry RetrieveEndEntityCertificateFromStorage(byte[] certificateHash)
        {
            byte[] endEntityCertificateEntrySerialized = StorageUtil.readFromStorage(certificateHash);
            if (endEntityCertificateEntrySerialized == null)
            {
                Logger.log("Can not find end entity certificate in storage");
                return new EndEntityCertificateEntry();
            }

            EndEntityCertificateEntry entityCertificateEntry =
                (EndEntityCertificateEntry) SerializationUtil.Deserialize(endEntityCertificateEntrySerialized);
            return entityCertificateEntry;
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
}