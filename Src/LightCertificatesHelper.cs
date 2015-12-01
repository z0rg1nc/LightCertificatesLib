using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using BtmI2p.AesHelper;
using BtmI2p.MiscUtil.Conversion;
using BtmI2p.MiscUtil.IO;
using BtmI2p.MiscUtils;
using CryptSharp.Utility;
using Xunit;

namespace BtmI2p.LightCertificates.Lib
{
    /**/
    public enum ECertGuidHashTypes : sbyte
    {
        None,
        // 8192, 8, 1
        Scrypt8Mb
    }
    public static class LightCertificatesHelper
    {
        public static bool CheckCertificateSignature(
            LightCertificate certificateToCheckSignature,
            LightCertificate signerCertificate
        )
        {
            var certData = GetCertDataForSignature(
                certificateToCheckSignature
            );
            return certificateToCheckSignature.Signatures
                .Where(x => x.SignerCertificateId == signerCertificate.Id)
                .Select(
                    certificateSignature => new SignedData()
                    {
                        Data = certData, 
                        Signature = certificateSignature
                    }
                )
                .Any(signerCertificate.VerifyData);
        }
        public static void SignCertificate(
            LightCertificate certificateToSign, 
            ILightCertificate signer, 
            byte[] pass
        )
        {
            if(certificateToSign == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => certificateToSign)
                );
            if(signer == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => signer)
                );
            if(pass == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => pass)
                );
            if(signer.OnlyPublic)
                throw new ArgumentException(
                    signer.MyNameOfProperty(e => e.OnlyPublic)
                );
            var certDataToSerialized = GetCertDataForSignature(certificateToSign);
            certificateToSign.Signatures.Add(
                signer.SignData(certDataToSerialized, pass).Signature
            );
        }

        public static byte[] GetCertDataForIdHash(
            LightCertificate certificateToSign)
        {
            Assert.NotNull(certificateToSign);
            using (var ms = new MemoryStream())
            {
                using (var writer = new EndianBinaryWriter(_littleConverter, ms))
                {
                    writer.Write(certificateToSign.SignType);
                    if (
                        certificateToSign.SignType
                        != (int)ELightCertificateSignType.None
                        )
                    {
                        writer.Write(certificateToSign.SignKeySize);
                        writer.Write(certificateToSign.PublicSignParameters);
                    }
                    writer.Write(certificateToSign.EncryptType);
                    if (
                        certificateToSign.EncryptType
                        != (int)ELightCertificateEncryptType.None
                        )
                    {
                        writer.Write(certificateToSign.EncryptKeySize);
                        writer.Write(certificateToSign.PublicEncryptParameters);
                    }
                }
                return ms.ToArray();
            }
        }

        private static byte[] GetCertDataForSignature(
            LightCertificate certificateToSign
        )
        {
            Assert.NotNull(certificateToSign);
            using (var ms = new MemoryStream())
            {
                using (var writer = new EndianBinaryWriter(_littleConverter, ms))
                {
                    writer.Write(certificateToSign.Id.ToByteArray());
                    writer.Write(GetCertDataForIdHash(certificateToSign));
                    if (
                        certificateToSign.AdditionalData != null 
                        && certificateToSign.AdditionalData.Length != 0
                    )
                        writer.Write(certificateToSign.AdditionalData);
                }
                return ms.ToArray();
            }
        }
        
        private static byte[] GetCertGuidHash(
            LightCertificate cert,
            ECertGuidHashTypes certGuidHashType,
            int hashSize
        )
        {
            var certDataToHash = GetCertDataForIdHash(cert);
            byte[] hash;
            if (certGuidHashType == ECertGuidHashTypes.Scrypt8Mb)
            {
                hash = SCrypt.ComputeDerivedKey(
                    certDataToHash,
                    certDataToHash,
                    8192,
                    8,
                    1,
                    1,
                    hashSize
                );
            }
            else
            {
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => certGuidHashType));
            }
            return hash;
        }

        public static bool CheckGuidHash(
            LightCertificate cert,
            ECertGuidHashTypes certGuidHashType,
            int hashSize
            )
        {
            Assert.NotNull(cert);
            cert.CheckMe();
            Assert.InRange(hashSize,1,16);
            var expectedHash = GetCertGuidHash(
                cert,
                certGuidHashType,
                hashSize
            );
            Assert.Equal(hashSize,expectedHash.Length);
            var actualHash = cert.Id.ToByteArray().Skip(16 - hashSize).Take(hashSize).ToArray();
            return expectedHash.SequenceEqual(actualHash);
        }

        public static LightCertificate GenerateSelfSignedCertificate(
            ELightCertificateSignType signType,
            int signBitCount,
            ELightCertificateEncryptType encryptType,
            int encryptBitCount,
            EPrivateKeysKeyDerivationFunction passKeyDerivationFunction,
            byte[] firstFixedCertGuidBytes,
            ECertGuidHashTypes certGuidHashType,
            string name,
            byte[] passToEncryptPrivateKeys,
            byte[] additionalData = null
        )
        {
            Assert.NotNull(firstFixedCertGuidBytes);
            Assert.InRange(firstFixedCertGuidBytes.Length,0,14);
            var g1 = Guid.NewGuid();
            var name1 = name ?? $"{g1}";
            var cert1 = GenerateSelfSignedCertificate(
                signType,
                signBitCount,
                encryptType,
                encryptBitCount,
                passKeyDerivationFunction,
                g1,
                name1,
                passToEncryptPrivateKeys,
                additionalData
            );
            var hashSize = 16 - firstFixedCertGuidBytes.Length - 1;
            byte[] hash = GetCertGuidHash(cert1, certGuidHashType, hashSize);
            Assert.Equal(hash.Length, hashSize);
            var newCertGuid = new Guid(
                firstFixedCertGuidBytes
                    .Concat(new[] { (byte)certGuidHashType})
                    .Concat(hash)
                    .ToArray()
            );
            cert1.Id = newCertGuid;
            cert1.Name = name ?? $"{newCertGuid}";
            cert1.Signatures.Clear();
            cert1.Signatures.Add(
                cert1.SignData(
                    GetCertDataForSignature(cert1),
                    passToEncryptPrivateKeys
                ).Signature
            );
            return cert1;
        }

        /**/
        public static LightCertificate GenerateSelfSignedCertificate(
            ELightCertificateSignType signType,
            int signBitCount,
            ELightCertificateEncryptType encryptType,
            int encryptBitCount,
            EPrivateKeysKeyDerivationFunction passKeyDerivationFunction,
            Guid certId,
            string name, 
            byte[] passToEncryptPrivateKeys,
            byte[] additionalData = null
        )
        {
            if(signType == ELightCertificateSignType.None)
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => signType)
                );
            if(signBitCount <= 0)
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => signBitCount)
                );
            if (encryptType == ELightCertificateEncryptType.None)
            {
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => encryptType)
                );
            }
            if(encryptBitCount <= 0)
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => encryptBitCount)
                );
            if(certId == Guid.Empty)
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => certId)
                );
            if(
                passToEncryptPrivateKeys == null
                || passToEncryptPrivateKeys.Length == 0
            )
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => passToEncryptPrivateKeys)
                );
            if(additionalData == null)
                additionalData =  new byte[0];
            var result = new LightCertificate();
            result.SignType = (int)signType;
            result.SignKeySize = signBitCount;
            if (signType == ELightCertificateSignType.Rsa)
            {
                using (var csp = new RSACryptoServiceProvider(signBitCount))
                {
                    csp.PersistKeyInCsp = false;
                    var publicRsaParameters 
                        = csp.ExportParameters(false);
                    var privateRsaParameters 
                        = csp.ExportParameters(true);
                    result.PublicSignParameters
                        = LightCertificate.WriteRsaParamterers(
                            publicRsaParameters,
                            false
                        );
                    result.PrivateSignParameters 
                        = new PassEncryptedData(
                            LightCertificate.WriteRsaParamterers(
                                privateRsaParameters,
                                true
                            ),
                            passKeyDerivationFunction,
                            passToEncryptPrivateKeys
                        );
                }
            }
            else
            {
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => signType)
                );
            }
            result.EncryptType = (int)encryptType;
            result.EncryptKeySize = encryptBitCount;
            if (encryptType == ELightCertificateEncryptType.Rsa)
            {
                using (var csp = new RSACryptoServiceProvider(encryptBitCount))
                {
                    csp.PersistKeyInCsp = false;
                    var publicRsaParameters
                        = csp.ExportParameters(false);
                    var privateRsaParameters
                        = csp.ExportParameters(true);
                    result.PublicEncryptParameters
                        = LightCertificate.WriteRsaParamterers(
                            publicRsaParameters,
                            false
                        );
                    result.PrivateEncryptParameters
                        = new PassEncryptedData(
                            LightCertificate.WriteRsaParamterers(
                                privateRsaParameters,
                                true
                            ),
                            passKeyDerivationFunction,
                            passToEncryptPrivateKeys
                        );
                }
            }
            else
            {
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => encryptType)
                );
            }
            result.Id = certId;
            result.Name = name;
            result.AdditionalData = additionalData;
            result.Signatures.Add(
                result.SignData(
                    GetCertDataForSignature(result),
                    passToEncryptPrivateKeys
                ).Signature
            );
            return result;
        }
        private static readonly LittleEndianBitConverter _littleConverter 
            = new LittleEndianBitConverter();
        public static byte[] EncryptAesKeyIvPair(
            AesKeyIvPair keyIvPair,
            LightCertificate certToEncrypt
        )
        {
            if(
                keyIvPair == null 
                || keyIvPair.Key == null 
                || keyIvPair.Iv == null 
                || certToEncrypt == null
            )
                throw new ArgumentNullException();
            if(keyIvPair.Key.Length != 32 || keyIvPair.Iv.Length != 16)
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => keyIvPair)
                );
            byte[] pairData = keyIvPair.ToBinaryArray();
            var result = certToEncrypt.EncryptData(pairData);
            return result;
        }

        public static AesKeyIvPair DecryptAesKeyIvPair(
            byte[] encryptedData,
            ILightCertificate privCertToDecrypt,
            byte[] certPass
        )
        {
            Assert.NotNull(encryptedData);
            Assert.NotNull(privCertToDecrypt);
            Assert.NotNull(certPass);
            var pairData = privCertToDecrypt.DecryptData(
                encryptedData, 
                certPass
            );
            Assert.Equal(48,pairData.Length);
            return AesKeyIvPair.FromBinaryArray(pairData);
        }
    }
}
