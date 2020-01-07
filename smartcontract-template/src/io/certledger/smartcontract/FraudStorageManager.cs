using System;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
    public enum FraudStatus
    {
        REPORTED = 0,
        APPROVED = 1,
        REJECTED = 2
    }

    [Serializable]
    public struct FraudEntry
    {
        public byte[] FraudId;
        public byte[] Reporter;
        public byte[] FakeButValidCertificateHash;
        public long ReportDate;
        public long ApproveRejectOperationDate;
        public FraudStatus Status;
    }

    [Serializable]
    public class FraudEntryMapEntry
    {
        public byte[][] fraudEntryArray;
    }

    public class FraudStorageManager
    {
        public static readonly byte[] FRAUD_LIST_STORAGE_KEY = StringUtil.StringToByteArray("FRAUD_LIST_STORAGE_KEY");

        public static readonly byte[] FRAUD_ID_STORAGE_PREFIX = StringUtil.StringToByteArray("FRAUD_ID_");


        public static void AddFraudReportToStorage(byte[] fraudId, byte[] reporter, byte[] fakeButValidCertificateHash)
        {
            FraudEntry fraudEntry = new FraudEntry();
            fraudEntry.FraudId = fraudId;
            fraudEntry.Reporter = reporter;
            fraudEntry.FakeButValidCertificateHash = fakeButValidCertificateHash;
            fraudEntry.ReportDate = TransactionContentUtil.retrieveTransactionTime();
            fraudEntry.Status = FraudStatus.REPORTED;

            byte[] fraudIdStorageKey = ArrayUtil.Concat(FRAUD_ID_STORAGE_PREFIX, fraudId);
            saveStorageForFraudIdIndex(fraudIdStorageKey, fraudEntry);
            AddFraudToList(FRAUD_LIST_STORAGE_KEY, fraudIdStorageKey);
        }

        public static FraudEntry ReadFraudEntry(byte[] fraudId)
        {
            FraudEntry fraudEntry = new FraudEntry();
            byte[] fraudIdStorageKey
                = ArrayUtil.Concat(FRAUD_ID_STORAGE_PREFIX, fraudId);
            byte[] fraudEntrySerialized = StorageUtil.readFromStorage(fraudIdStorageKey);
            if (fraudEntrySerialized == null)
            {
                return fraudEntry;
            }

            return (FraudEntry) SerializationUtil.Deserialize(fraudEntrySerialized);
        }

        public static void updateFraudEntry(FraudEntry fraudEntry)
        {
            byte[] fraudIdStorageKey
                = ArrayUtil.Concat(FRAUD_ID_STORAGE_PREFIX, fraudEntry.FraudId);
            saveStorageForFraudIdIndex(fraudIdStorageKey, fraudEntry);
        }

        private static void AddFraudToList(byte[] storageKey, byte[] newDraudIdStorageKey)
        {
            FraudEntryMapEntry fraudEntryMapEntry;

            byte[] fraudEntryMapEntrySerialized = StorageUtil.readFromStorage(storageKey);
            if (fraudEntryMapEntrySerialized == null)
            {
                fraudEntryMapEntry = new FraudEntryMapEntry();
                fraudEntryMapEntry.fraudEntryArray = new byte[1][];
                fraudEntryMapEntry.fraudEntryArray[0] = newDraudIdStorageKey;
            }
            else
            {
                fraudEntryMapEntry =
                    (FraudEntryMapEntry) SerializationUtil.Deserialize(fraudEntryMapEntrySerialized);
                byte[][] newFraudEntryArray =
                    new byte[fraudEntryMapEntry.fraudEntryArray.Length + 1][];
                newFraudEntryArray[0] = newDraudIdStorageKey;
                for (int i = 0; i < fraudEntryMapEntry.fraudEntryArray.Length; i++)
                {
                    newFraudEntryArray[i + 1] = fraudEntryMapEntry.fraudEntryArray[i];
                }

                fraudEntryMapEntry.fraudEntryArray = newFraudEntryArray;
            }

            fraudEntryMapEntrySerialized = SerializationUtil.Serialize(fraudEntryMapEntry);
            StorageUtil.saveToStorage(storageKey, fraudEntryMapEntrySerialized);
        }

        private static void saveStorageForFraudIdIndex(byte[] fraudIdStorageKey, FraudEntry fraudEntry)
        {
            byte[] fraudEntrySerialized = SerializationUtil.Serialize(fraudEntry);
            StorageUtil.saveToStorage(fraudIdStorageKey,
                fraudEntrySerialized);
        }
    }
}