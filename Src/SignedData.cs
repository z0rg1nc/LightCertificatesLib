using System;
using System.Security.Cryptography;
using System.Text;
using BtmI2p.MiscUtils;
using NLog;

namespace BtmI2p.LightCertificates.Lib
{
    [Serializable]
    public class SignedData<T1> : SignedData
    {
        public SignedData()
        {
        }

        public SignedData(SignedData data)
        {
            Data = data.Data;
            Signature = data.Signature;
        }

        public SignedData(
            T1 value, 
            ILightCertificate cert, 
            byte[] pass
        )
        {
            var dataToSign = Serialize(value);
            var signedData = cert.SignData(dataToSign, pass);
            Data = signedData.Data;
            Signature = signedData.Signature;
        }
        public static byte[] Serialize(T1 obj)
        {
            return Encoding.UTF8.GetBytes(
                obj.WriteObjectToJson()
            );
        }

        public static T1 Deserialize(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => data)
                );
            return Encoding.UTF8.GetString(
                data
            ).ParseJsonToType<T1>();
        }

        public SignedData<T2> To<T2>()
        {
            return new SignedData<T2>()
            {
                Data = Data, 
                Signature = Signature
            };
        }
        public T1 GetValue()
        {
            if (Data == null)
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.Data)
                );
            return Deserialize(Data);
        }
        public T1 GetValue(ILightCertificate certToVerifyData)
        {
            if (certToVerifyData == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => certToVerifyData)
                );
            if (Data == null)
                throw new ArgumentNullException(
                    this.MyNameOfProperty(e => e.Data)
                );
            if (certToVerifyData.Id != Signature.SignerCertificateId)
                throw new ArgumentException(
                    certToVerifyData.MyNameOfProperty(e => e.Id)
                );
            if (!certToVerifyData.VerifyData(this))
            {
                throw new CryptographicException(
                    "Verification failed"
                );
            }
            return Deserialize(Data);
        }

        private static readonly Logger _logger 
            = LogManager.GetCurrentClassLogger();
        public static SignedData<T1> GetSignedData(
            T1 value,
            ILightCertificate cert,
            byte[] pass
        )
        {
            var dataToSign = Serialize(value);
            var signedData = cert.SignData(dataToSign, pass);
            return new SignedData<T1>()
            {
                Data = signedData.Data,
                Signature = signedData.Signature
            };
        }

        public static SignedData<T1> GetSignedDataWithEmptySignature(
            T1 value,
            LightCertificate cert
        )
        {
            var dataToSign = Serialize(value);
            return new SignedData<T1>()
            {
                Data = dataToSign,
                Signature = new LightCertificateSignature()
                {
                    SignatureBytes = null,
                    SignerCertificateId = cert.Id
                }
            };
        }
    }
    [Serializable]
    public class SignedData
    {
        public byte[] Data;
        public LightCertificateSignature Signature;
    }
    [Serializable]
    public class LightCertificateSignature
    {
        public Guid SignerCertificateId;
        public byte[] SignatureBytes;
    }
}
