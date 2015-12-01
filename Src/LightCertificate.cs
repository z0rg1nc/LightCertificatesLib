using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BtmI2p.CryptFile.Lib;
using BtmI2p.MiscUtil.Conversion;
using BtmI2p.MiscUtil.IO;
using BtmI2p.MiscUtils;
using Xunit;

namespace BtmI2p.LightCertificates.Lib
{
    public enum ELightCertificateSignType
    {
        None,
        Rsa
    }

    public enum ELightCertificateEncryptType
    {
        None,
        Rsa
    }

    public enum EPrivateKeysKeyDerivationFunction
    {
        // 8192, 8, 1
        ScryptDefault
    }

    public class PassEncryptedData : ICheckable
    {
        public int KeyDerivationFunctionType 
            = (int)EPrivateKeysKeyDerivationFunction.ScryptDefault;
        public byte[] Salt;
        public byte[] AesEncryptedData;

        public PassEncryptedData()
        {
            Salt = new byte[32];
            MiscFuncs.GetRandomBytes(Salt);
        }

        public PassEncryptedData(
            byte[] originData,
            EPrivateKeysKeyDerivationFunction keyDerivationFunction,
            byte[] pass
            ) : this()
        {
            KeyDerivationFunctionType 
                = (int)keyDerivationFunction;
            if (
                keyDerivationFunction
                == EPrivateKeysKeyDerivationFunction.ScryptDefault
            )
            {
                AesEncryptedData = CryptConfigFileHelper.Encrypt(
                    originData,
                    pass,
                    Salt
                );
            }
            else
            {
                throw new ArgumentOutOfRangeException(
                    MyNameof.GetLocalVarName(() => keyDerivationFunction)
                );
            }
        }

        public byte[] GetOriginData(byte[] pass)
        {
            if (
                KeyDerivationFunctionType
                == (int)EPrivateKeysKeyDerivationFunction.ScryptDefault
            )
            {
                return CryptConfigFileHelper.Decrypt(
                    AesEncryptedData,
                    pass,
                    Salt
                );
            }
            else
            {
                throw new ArgumentOutOfRangeException(
                    this.MyNameOfProperty(e => e.KeyDerivationFunctionType)
                );
            }
        }

        public void CheckMe()
        {
            if(AesEncryptedData == null)
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.AesEncryptedData)
                );
            if(Salt == null)
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.Salt)
                );
        }
    }
    public interface ILightCertificate
    {
        /**/
        Guid Id { get; set; }
        bool OnlyPublic { get; set; }
        bool IsPassValid(byte[] pass);
        /**/
        bool VerifyData(SignedData signedData);
        SignedData SignData(
            byte[] data, 
            byte[] pass
        );
        /**/
        byte[] EncryptData(byte[] data);
        byte[] DecryptData(
            byte[] encryptedData,
            byte[] pass
        );
        /**/
        void ChangePass(byte[] oldPass, byte[] newPass);
    }
    
    [Serializable]
    public class LightCertificate : 
        IEquatable<LightCertificate>,
        ILightCertificate
    {
        /**/
        private bool _onlyPublic = false;
        public bool OnlyPublic
        {
            get { return _onlyPublic; }
            set { _onlyPublic = value; }
        }
        public byte[] AdditionalData = new byte[0];
        private Guid _id = Guid.NewGuid();
        public Guid Id
        {
            get { return _id; } 
            set { _id = value; }
        }
        public string Name = string.Empty;
        public List<LightCertificateSignature> Signatures =
            new List<LightCertificateSignature>();
        /**/
        public int SignType
            = (int)ELightCertificateSignType.None;
        public int SignKeySize = 0;
        public byte[] PublicSignParameters;
        public PassEncryptedData PrivateSignParameters;
        /**/
        public int EncryptType
            = (int)ELightCertificateEncryptType.None;
        public int EncryptKeySize = 0;
        public byte[] PublicEncryptParameters;
        public PassEncryptedData PrivateEncryptParameters;
        /**/

        public static async Task CorruptByteArrays(
            params byte[][] byteArrayArray
        )
        {
            foreach (byte[] b in byteArrayArray)
            {
                if(b != null)
                    MiscFuncs.GetRandomBytes(b);
            }
        }

        public static async Task CorruptRsaParameters(
            RSAParameters rsaParameters
        )
        {
            await CorruptByteArrays(
                rsaParameters.Exponent,
                rsaParameters.Modulus,
                rsaParameters.P,
                rsaParameters.Q,
                rsaParameters.DP,
                rsaParameters.DQ,
                rsaParameters.InverseQ,
                rsaParameters.D
            ).ConfigureAwait(false);
        }

        public static byte[] WriteRsaParamterers(
            RSAParameters rsaParameters,
            bool writePrivate
        )
        {
            using (var ms = new MemoryStream())
            {
                using (
                    var writer = new EndianBinaryWriter(
                        _littleConverter,
                        ms
                    )
                )
                {
                    writer.Write(rsaParameters.Exponent.Length);
                    writer.Write(rsaParameters.Exponent);
                    writer.Write(rsaParameters.Modulus.Length);
                    writer.Write(rsaParameters.Modulus);
                    if (writePrivate)
                    {
                        writer.Write(rsaParameters.P.Length);
                        writer.Write(rsaParameters.P);
                        writer.Write(rsaParameters.Q.Length);
                        writer.Write(rsaParameters.Q);
                        writer.Write(rsaParameters.DP.Length);
                        writer.Write(rsaParameters.DP);
                        writer.Write(rsaParameters.DQ.Length);
                        writer.Write(rsaParameters.DQ);
                        writer.Write(rsaParameters.InverseQ.Length);
                        writer.Write(rsaParameters.InverseQ);
                        writer.Write(rsaParameters.D.Length);
                        writer.Write(rsaParameters.D);
                    }
                }
                var result = ms.ToArray();
                //_rng.GetBytes(ms.GetBuffer());
                return result;
            }
        }

        public static RSAParameters ReadRsaParameters(
            byte[] buffer,
            bool readPrivate
        )
        {
            var result = new RSAParameters();
            using (var ms = new MemoryStream(buffer))
            {
                using (
                    var reader = new EndianBinaryReader(
                        _littleConverter,
                        ms
                    )
                )
                {
                    result.Exponent = reader.ReadBytesOrThrow(reader.ReadInt32());
                    result.Modulus = reader.ReadBytesOrThrow(reader.ReadInt32());
                    /**/
                    if (readPrivate)
                    {
                        result.P = reader.ReadBytesOrThrow(reader.ReadInt32());
                        result.Q = reader.ReadBytesOrThrow(reader.ReadInt32());
                        result.DP = reader.ReadBytesOrThrow(reader.ReadInt32());
                        result.DQ = reader.ReadBytesOrThrow(reader.ReadInt32());
                        result.InverseQ = reader.ReadBytesOrThrow(reader.ReadInt32());
                        result.D = reader.ReadBytesOrThrow(reader.ReadInt32());
                    }
                }
                //_rng.GetBytes(ms.GetBuffer());
            }
            return result;
        }

        private static readonly LittleEndianBitConverter _littleConverter
            = new LittleEndianBitConverter();
        /**/
        public void CheckMe(
            bool checkPrivateKeys = false, 
            byte[] privateKeysPass = null
        )
        {
            if (OnlyPublic && checkPrivateKeys)
            {
                throw new ArgumentException(
                    MyNameof.GetLocalVarName(() => checkPrivateKeys)
                );
            }
            if (Id == Guid.Empty)
            {
                throw new ArgumentException(
                    this.MyNameOfProperty(e => e.Id)
                );
            }
            if (AdditionalData == null)
            {
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.AdditionalData)
                );
            }
            if(Signatures == null)
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.Signatures)
                );
            if (
                checkPrivateKeys 
                && privateKeysPass == null
            )
            {
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => privateKeysPass)
                );
            }
            if (SignType != (int)ELightCertificateSignType.None)
            {
                if (SignType == (int)ELightCertificateSignType.Rsa)
                {
                    if(SignKeySize <= 0)
                        throw new ArgumentOutOfRangeException(
                            this.MyNameOfProperty(e => e.SignKeySize)
                        );
                    if(
                        PublicSignParameters == null
                    )
                        throw new ArgumentNullException(
                            this.MyNameOfProperty(e => e.PublicSignParameters)
                        );
                    var publicRsaParameters = ReadRsaParameters(
                        PublicSignParameters,
                        false
                    );
                    using (var csp = GetRsaCsp())
                    {
                        csp.ImportParameters(
                            publicRsaParameters
                        );
                        if(csp.KeySize != SignKeySize)
                            throw new ArgumentException(
                                this.MyNameOfProperty(e => e.PublicSignParameters)
                            );
                    }
                    if (checkPrivateKeys)
                    {
                        if(PrivateSignParameters == null)
                            throw new ArgumentNullException(
                                this.MyNameOfProperty(e => e.PrivateSignParameters)
                            );
                        PrivateSignParameters.CheckMe();
                        var privateRsaParameters = ReadRsaParameters(
                            PrivateSignParameters.GetOriginData(
                                privateKeysPass
                                ),
                            true
                        );
                        if (
                            !privateRsaParameters.Exponent.SequenceEqual(
                                publicRsaParameters.Exponent
                            )
                            ||
                            !privateRsaParameters.Modulus.SequenceEqual(
                                publicRsaParameters.Modulus
                            )
                        )
                        {
                            throw new ArgumentException(
                                this.MyNameOfProperty(e => e.PrivateSignParameters)
                            );
                        }
                        using (var csp = GetRsaCsp())
                        {
                            csp.ImportParameters(
                                privateRsaParameters
                            );
                            if (csp.KeySize != SignKeySize)
                            {
                                throw new ArgumentException(
                                    this.MyNameOfProperty(e => e.PrivateSignParameters)
                                );
                            }
                        }
                    }
                }
                else
                {
                    throw new ArgumentOutOfRangeException(
                        this.MyNameOfProperty(e => e.SignType)
                    );
                }
            }
            if (EncryptType != (int)ELightCertificateEncryptType.None)
            {
                if (EncryptType == (int)ELightCertificateEncryptType.Rsa)
                {
                    if (EncryptKeySize <= 0)
                        throw new ArgumentOutOfRangeException(
                            this.MyNameOfProperty(e => e.EncryptKeySize)
                        );
                    if (
                        PublicEncryptParameters == null
                    )
                        throw new ArgumentNullException(
                            this.MyNameOfProperty(e => e.PublicEncryptParameters)
                        );
                    var publicRsaParameters = ReadRsaParameters(
                        PublicEncryptParameters,
                        false
                    );
                    using (var csp = GetRsaCsp())
                    {
                        csp.ImportParameters(
                            publicRsaParameters
                        );
                        if (csp.KeySize != SignKeySize)
                            throw new ArgumentException(
                                this.MyNameOfProperty(e => e.PublicEncryptParameters)
                            );
                    }
                    if (checkPrivateKeys)
                    {
                        if (PrivateEncryptParameters == null)
                            throw new ArgumentNullException(
                                this.MyNameOfProperty(e => e.PrivateEncryptParameters)
                            );
                        PrivateEncryptParameters.CheckMe();
                        var privateRsaParameters = ReadRsaParameters(
                            PrivateEncryptParameters.GetOriginData(
                                privateKeysPass
                            ),
                            true
                        );
                        if (
                            !privateRsaParameters.Exponent.SequenceEqual(
                                publicRsaParameters.Exponent
                            )
                            ||
                            !privateRsaParameters.Modulus.SequenceEqual(
                                publicRsaParameters.Modulus
                            )
                        )
                        {
                            throw new ArgumentException(
                                this.MyNameOfProperty(e => e.PrivateEncryptParameters)
                            );
                        }
                        using (var csp = GetRsaCsp())
                        {
                            csp.ImportParameters(
                                privateRsaParameters
                            );
                            if (csp.KeySize != SignKeySize)
                            {
                                throw new ArgumentException(
                                    this.MyNameOfProperty(e => e.PrivateEncryptParameters)
                                );
                            }
                        }
                    }
                }
                else
                {
                    throw new ArgumentOutOfRangeException(
                        this.MyNameOfProperty(e => e.EncryptType)
                    );
                }
            }
            if(Signatures.Any(_ => _.SignerCertificateId == this.Id))
                Assert.True(
                    LightCertificatesHelper.CheckCertificateSignature(
                        this,
                        this
                    )
                );
        }
        /**/
        public bool Equals(LightCertificate other)
        {
            if (other == null)
                return false;
            try
            {
                CheckMe();
                other.CheckMe();
            }
            catch
            {
                return false;
            }
            if (Id != other.Id)
                return false;
            if (
                SignType != other.SignType
                || EncryptType != other.EncryptType
            )
                return false;
            if (SignType != (int)ELightCertificateSignType.None)
            {
                if(
                    !PublicSignParameters.SequenceEqual(
                        other.PublicSignParameters
                    )
                )
                    return false;
            }
            if (EncryptType != (int)ELightCertificateEncryptType.None)
            {
                if(
                    !PublicEncryptParameters.SequenceEqual(
                        other.PublicEncryptParameters
                    )
                )
                    return false;
            }
            return true;
        }
        public bool IsPassValid(byte[] pass)
        {
            if(OnlyPublic)
                throw new ArgumentException(
                    this.MyNameOfProperty(e => e.OnlyPublic)
                );
            try
            {
                if(SignType != (int)ELightCertificateSignType.None)
                    PrivateSignParameters.GetOriginData(pass);
                if (EncryptType != (int) ELightCertificateEncryptType.None)
                    PrivateEncryptParameters.GetOriginData(pass);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public LightCertificate GetOnlyPublic()
        {
            return new LightCertificate()
            {
                Id = Id,
                Signatures = Signatures,
                Name = Name,
                AdditionalData = AdditionalData,
                OnlyPublic = true,
                SignType = SignType,
                PublicSignParameters = PublicSignParameters,
                SignKeySize = SignKeySize,
                PrivateSignParameters = null,
                EncryptType = EncryptType,
                PublicEncryptParameters = PublicEncryptParameters,
                EncryptKeySize = EncryptKeySize,
                PrivateEncryptParameters = null
            };
        }
        public bool VerifyData(SignedData signedData)
        {
            if (signedData == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => signedData)
                );
            if (signedData.Signature == null)
                throw new ArgumentNullException(
                    "signedData.Signature"
                );
            if (signedData.Signature.SignerCertificateId != Id)
                throw new InvalidOperationException(
                    "Signer id != certificate id"
                );
            if (SignType == (int)ELightCertificateSignType.Rsa)
            {
                var publicRsaParameters = ReadRsaParameters(
                    PublicSignParameters,
                    false
                );
                using (var csp = GetRsaCsp())
                {
                    csp.ImportParameters(publicRsaParameters);
                    using (var hashAlg = new SHA256Managed())
                    {
                        return csp.VerifyData(
                            signedData.Data,
                            hashAlg,
                            signedData.Signature.SignatureBytes
                        );
                    }
                }
            }
            throw new ArgumentOutOfRangeException(
                this.MyNameOfProperty(e => e.SignType)
            );
        }

        private static RSACryptoServiceProvider GetRsaCsp()
        {
            var result = new RSACryptoServiceProvider();
            result.PersistKeyInCsp = false;
            return result;
        }

        public SignedData SignData(
            byte[] data, 
            byte[] pass
        )
        {
            if (data == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => data)
                );
            if (data.Length == 0)
                throw new ArgumentOutOfRangeException("data.Length == 0");
            if (pass == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => pass)
                );
            if(OnlyPublic)
                throw new ArgumentOutOfRangeException(
                    this.MyNameOfProperty(e => e.OnlyPublic)
                );
            if (SignType == (int)ELightCertificateSignType.Rsa)
            {
                var privateRsaParameters = ReadRsaParameters(
                    PrivateSignParameters.GetOriginData(pass),
                    true
                );
                using (var csp = GetRsaCsp())
                {
                    csp.ImportParameters(privateRsaParameters);
                    using (var hashAlg = new SHA256Managed())
                    {
                        return new SignedData()
                        {
                            Data = data,
                            Signature = new LightCertificateSignature()
                            {
                                SignerCertificateId = Id,
                                SignatureBytes = csp.SignData(data, hashAlg)
                            }
                        };
                    }
                }
            }
            throw new ArgumentOutOfRangeException(
                this.MyNameOfProperty(e => e.SignType)
            );
        }

        public byte[] EncryptData(byte[] data)
        {
            Assert.NotNull(data);
            Assert.True(data.Length > 0);
            if (EncryptType == (int)ELightCertificateSignType.Rsa)
            {
                var publicRsaParameters = ReadRsaParameters(
                    PublicEncryptParameters,
                    false
                );
                using (var csp = GetRsaCsp())
                {
                    csp.ImportParameters(publicRsaParameters);
                    return csp.Encrypt(data, true);
                }
            }
            throw new ArgumentOutOfRangeException(
                this.MyNameOfProperty(e => e.EncryptType)
            );
        }

        public byte[] DecryptData(
            byte[] encryptedData, 
            byte[] pass
        )
        {
            if (encryptedData == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => encryptedData)
                );
            if (encryptedData.Length == 0)
                throw new ArgumentOutOfRangeException(
                    "encryptedData.Length == 0"
                );
            if (pass == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => pass)
                );
            if (
                EncryptType 
                == (int)ELightCertificateEncryptType.Rsa
            )
            {
                var privateRsaParameters = ReadRsaParameters(
                    PrivateEncryptParameters.GetOriginData(
                        pass
                    ),
                    true
                );
                using (var csp = GetRsaCsp())
                {
                    csp.ImportParameters(privateRsaParameters);
                    return csp.Decrypt(encryptedData, true);
                }
            }
            throw new ArgumentOutOfRangeException(
                this.MyNameOfProperty(e => e.EncryptType)
            );
        }

        public void ChangePass(byte[] oldPass, byte[] newPass)
        {
            if(oldPass == null || oldPass.Length == 0)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => oldPass)
                );
            if(newPass == null || newPass.Length == 0)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => newPass)
                );
            if(OnlyPublic)
                throw new InvalidOperationException(
                    this.MyNameOfProperty(e => e.OnlyPublic)
                );
            if(!IsPassValid(oldPass))
                throw new ArgumentException(
                    MyNameof.GetLocalVarName(() => oldPass)
                );
            if (SignType != (int) ELightCertificateSignType.None)
            {
                var curSignPrivateData = PrivateSignParameters.GetOriginData(
                    oldPass
                );
                PrivateSignParameters = new PassEncryptedData(
                    curSignPrivateData,
                    (EPrivateKeysKeyDerivationFunction)
                        PrivateSignParameters.KeyDerivationFunctionType,
                    newPass
                );
            }
            if (EncryptType != (int) ELightCertificateEncryptType.None)
            {
                var curEncryptPrivateData 
                    = PrivateEncryptParameters.GetOriginData(
                        oldPass
                    );
                PrivateEncryptParameters = new PassEncryptedData(
                    curEncryptPrivateData,
                    (EPrivateKeysKeyDerivationFunction)
                        PrivateEncryptParameters.KeyDerivationFunctionType,
                    newPass
                );
            }
        }

        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }
    }
}
