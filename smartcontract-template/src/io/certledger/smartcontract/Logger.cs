#if NEO
using CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract.platform.neo;
#endif
using System;

namespace CertLedgerBusinessSCTemplate.src.io.certledger.smartcontract
{
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

            log("DNSName Count : ");
            log(certificate.DNsNames.Length);
            foreach (var dNsName in certificate.DNsNames)
            {
                Logger.log(dNsName);
            }
        }

        public static void log(string fieldName, object value)
        {
#if NEO
            NeoVMLogger.log(fieldName, value);
#endif
#if NET_CORE
                            Console.WriteLine(fieldName);
                            Console.WriteLine(value);
#endif
        }

        public static void log(string message, byte[] argument)
        {
#if NEO
            NeoVMLogger.log(message, argument);
#endif
#if NET_CORE
                            Console.WriteLine(message);
                            Console.WriteLine(argument);
#endif
        }

        public static void log(object message)
        {
#if NEO
            NeoVMLogger.log(message);
#endif
#if NET_CORE
                            Console.WriteLine(message);
#endif
        }

        public static void log(bool message)
        {
#if NEO
            NeoVMLogger.log(message);
#endif
#if NET_CORE
                            Console.WriteLine(message);
#endif
        }

        public static void log(string condition, bool status)
        {
#if NEO
            NeoVMLogger.log(condition, status);
#endif
#if NET_CORE
                            Console.WriteLine(condition);
                            Console.WriteLine(status);
#endif
        }
    }
}