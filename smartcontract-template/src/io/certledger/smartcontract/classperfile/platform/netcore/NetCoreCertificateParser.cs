using System;
using System.Collections;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using io.certledger.smartcontract.allinone.platfom.netcore;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace io.certledger.smartcontract.business.util
{
    public class NetCoreCertificateParser
    {
        public static Certificate Parse(byte[] certBytes)
        {
            Certificate certificate = new Certificate();

            try
            {
                X509Certificate2 x509 = new X509Certificate2(certBytes);
                certificate.IsLoaded = true;
                certificate.Version = x509.Version;
                certificate.BasicConstraints = retrieveBasicContraints(x509);
                certificate.KeyUsage = retrieveKeyUsage(x509);
                Validity validity = new Validity();
                validity.NotBefore = new DateTimeOffset(x509.NotBefore).ToUnixTimeSeconds();
                validity.NotAfter = new DateTimeOffset(x509.NotAfter).ToUnixTimeSeconds();
                certificate.Validity = validity;

                X509CertificateParser x509CertificateParser = new X509CertificateParser();
                X509Certificate bouncyCertificate = x509CertificateParser.ReadCertificate(certBytes);

                certificate.SerialNumber = new BigInteger(bouncyCertificate.SerialNumber.ToByteArray());
                certificate.TbsCertificate = bouncyCertificate.GetTbsCertificate();
                certificate.TBSSignatureAlgorithm = bouncyCertificate.CertificateStructure.TbsCertificate.Signature.GetEncoded();
                certificate.SignatureAlgorithm = bouncyCertificate.CertificateStructure.SignatureAlgorithm.GetEncoded();
                certificate.Signature = bouncyCertificate.GetSignature();
                certificate.SubjectPublicKeyInfo = bouncyCertificate.CertificateStructure.SubjectPublicKeyInfo.GetEncoded();
                certificate.SubjectKeyIdentifier = retrieveSubjectKeyIdentifier(bouncyCertificate);
                certificate.AuthorityKeyIdentifier = retrieveAuthorityKeyIdentifier(bouncyCertificate);
                certificate.ExtendedKeyUsage = retrieveExtendedKeyUsageOIDs(bouncyCertificate);
                certificate.Issuer = RetrieveIssuerName(bouncyCertificate);
                certificate.Subject = RetrieveSubjectName(bouncyCertificate);
                certificate.DNsNames = retrieveDnsNames(bouncyCertificate);
                return certificate;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return certificate;
            }
        }

        private static byte[][] retrieveDnsNames(X509Certificate bouncyCertificate)
        {
            var subjectAlternativeNames = bouncyCertificate.GetSubjectAlternativeNames();
            List<byte[]> dnsNameList = new List<byte[]>();
            foreach (IList subjectAlternativeNameValueList in subjectAlternativeNames)
            {
                int tag = (int) subjectAlternativeNameValueList[0];
                string stringValue = (string) subjectAlternativeNameValueList[1];

                if (GeneralName.DnsName == tag)
                {
                    dnsNameList.Add(StringUtil.StringToByteArray(stringValue));
                }
            }

            return dnsNameList.ToArray();
        }

        public static KeyUsage retrieveKeyUsage(X509Certificate2 x509Certificate)
        {
            KeyUsage keyUsage = new KeyUsage();
            var x509CertificateExtension = x509Certificate.Extensions[OIDS.OID_KEY_USAGE_EXTENSION];
            if (x509CertificateExtension != null)
            {
                X509KeyUsageExtension x509KeyUsageExtension = (X509KeyUsageExtension) x509CertificateExtension;
                keyUsage.HasKeyUsageExtension = true;
                keyUsage.IsCritical = x509KeyUsageExtension.Critical;
                keyUsage.KeyUsageFlags = (KeyUsageFlags) Convert.ToInt32(x509KeyUsageExtension.KeyUsages);
            }
            else
            {
                keyUsage.HasKeyUsageExtension = false;
            }

            return keyUsage;
        }

        public static BasicConstraints retrieveBasicContraints(X509Certificate2 x509Certificate)
        {
            BasicConstraints basicConstraints = new BasicConstraints();
            var x509CertificateExtension = x509Certificate.Extensions[OIDS.OID_BASIC_CONSTRAINT_EXTENSION];
            if (x509CertificateExtension != null)
            {
                X509BasicConstraintsExtension basicConstraintsExtension = (X509BasicConstraintsExtension) x509CertificateExtension;
                basicConstraints.HasBasicConstraints = true;
                basicConstraints.HasPathLengthConstraint = basicConstraintsExtension.HasPathLengthConstraint;
                basicConstraints.IsCa = basicConstraintsExtension.CertificateAuthority;
                basicConstraints.MaxPathLen = basicConstraintsExtension.PathLengthConstraint;
            }
            else
            {
                basicConstraints.HasBasicConstraints = true;
                basicConstraints.IsCa = false;
                basicConstraints.HasPathLengthConstraint = false;
            }

            return basicConstraints;
        }

        public static SubjectKeyIdentifier retrieveSubjectKeyIdentifier(X509Certificate x509Certificate)
        {
            SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
            X509Extension x509Extension = x509Certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(new DerObjectIdentifier(OIDS.OID_SUBJECT_KEY_IDENTIFIER_EXTENSION));
            if (x509Extension != null)
            {
                Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier subjectKeyIdentifierExtension = Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier.GetInstance(x509Extension);


                subjectKeyIdentifier.HasSubjectKeyIdentifierExtension = true;
                subjectKeyIdentifier.IsCritical = x509Extension.IsCritical;
                subjectKeyIdentifier.keyIdentifier = subjectKeyIdentifierExtension.GetKeyIdentifier();
                //todo: add issuer and serial fields.
            }
            else
            {
                subjectKeyIdentifier.HasSubjectKeyIdentifierExtension = false;
            }

            return subjectKeyIdentifier;
        }

        public static AuthorityKeyIdentifier retrieveAuthorityKeyIdentifier(X509Certificate x509Certificate)
        {
            AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
            X509Extension x509Extension = x509Certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(new DerObjectIdentifier(OIDS.OID_AUTHORITY_KEY_IDENTIFIER_EXTENSION));
            if (x509Extension != null)
            {
                Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier authorityKeyIdentifierExtension = Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier.GetInstance(x509Extension);
                authorityKeyIdentifier.HasAuthorityKeyIdentifier = true;
                authorityKeyIdentifier.IsCritical = x509Extension.IsCritical;
                authorityKeyIdentifier.keyIdentifier = authorityKeyIdentifierExtension.GetKeyIdentifier();
                //todo: add issuer and serial fields.
            }
            else
            {
                authorityKeyIdentifier.HasAuthorityKeyIdentifier = false;
            }

            return authorityKeyIdentifier;
        }

        public static ExtendedKeyUsage retrieveExtendedKeyUsageOIDs(X509Certificate x509Certificate)
        {
            ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();

            X509Extension x509Extension = x509Certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(new DerObjectIdentifier(OIDS.OID_EXTENDED_KEY_USAGE_EXTENSION));
            if (x509Extension != null)
            {
                Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage extendedKeyUsageExtension = Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage.GetInstance(x509Extension);
                extendedKeyUsage.HasExtendedKeyUsageExtension = true;
                extendedKeyUsage.IsCritical = x509Extension.IsCritical;
                IList allUsages = extendedKeyUsageExtension.GetAllUsages();
                extendedKeyUsage.Count = allUsages.Count;

                List<byte[]> purposeOidList = new List<byte[]>(allUsages.Count);
                foreach (DerObjectIdentifier derObjectIdentifier in allUsages)
                {
                    purposeOidList.Add(StringUtil.StringToByteArray(derObjectIdentifier.Id));
                }

                extendedKeyUsage.Oids = purposeOidList.ToArray();
            }
            else
            {
                extendedKeyUsage.HasExtendedKeyUsageExtension = false;
            }

            return extendedKeyUsage;
        }

        private static Name RetrieveSubjectName(X509Certificate bouncyCertificate)
        {
            return RetriveName(bouncyCertificate.SubjectDN);
        }

        private static Name RetrieveIssuerName(X509Certificate bouncyCertificate)
        {
            return RetriveName(bouncyCertificate.IssuerDN);
        }

        private static Name RetriveName(X509Name x509Name)
        {
            Name name = new Name();
            name.isEmpty = x509Name.ToString().Length == 0;
            var commonNameList = x509Name.GetValueList(X509Name.CN);
            if (commonNameList != null && commonNameList.Count != 0)
            {
                name.CommonName = StringUtil.StringToByteArray(commonNameList[0].ToString());
            }

            //todo - add other fields if required
            return name;
        }
    }
}