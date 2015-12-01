using System;
using System.Diagnostics;
using System.Linq;
using System.Text;
using BtmI2p.AesHelper;
using BtmI2p.LightCertificates.Lib;
using BtmI2p.MiscUtils;
using Xunit;
using Xunit.Abstractions;

namespace BtmI2p.LightCertificates.Tests
{
    public class UnitTest1
    {
        private readonly ITestOutputHelper _output;
        public UnitTest1(ITestOutputHelper output)
        {
	        _output = output;
        }
        [Fact]
        public void TestPerformance()
        {
            var allCertPass = Encoding.UTF8.GetBytes("TestPassword");
            var testCertificate 
                = LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa,
                    2048,
                    ELightCertificateEncryptType.Rsa,
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault, 
                    Guid.NewGuid(),
                    "TestCertificate",
                    allCertPass
                );
            byte[] testData = Enumerable
                .Range(0, 10000)
                .Select(x => (byte) (x%256))
                .ToArray();
            var sw = new Stopwatch();
            sw.Start();
            const int calc1It = 10;
            int a = 0;
            for (int i = 0; i < calc1It; i++)
            {
                var sd = testCertificate.SignData(testData, allCertPass);
                a += sd.Signature.SignatureBytes[0];
            }
            sw.Stop();
            _output.WriteLine(
                "{0} ms for calculating {1} signatures {2}", 
                sw.ElapsedMilliseconds,
                calc1It,
                a
            );
            var testSignedData = testCertificate.SignData(testData, allCertPass);
            const int calc2It = 5000;
            int b = 0;
            var sw2 = new Stopwatch();
            sw2.Start();
            for (int i = 0; i < calc2It; i++)
            {
                bool verifiedData = testCertificate.VerifyData(testSignedData);
                b += verifiedData ? 1 : 0;
            }
            sw2.Stop();
            _output.WriteLine(
                "{0} ms for verifying {1} signatures {2}",
                sw2.ElapsedMilliseconds,
                calc2It,
                b
            );
        }

        [Fact]
        public void TestSerializeCertificate()
        {
            var testCertificate = LightCertificatesHelper.GenerateSelfSignedCertificate(
                ELightCertificateSignType.Rsa,
                512,
                ELightCertificateEncryptType.Rsa,
                512,
                EPrivateKeysKeyDerivationFunction.ScryptDefault, 
                Guid.NewGuid(),
                "TestCertificate",
                Encoding.UTF8.GetBytes("TestPassword")
            );
            var serializedTestCert = testCertificate.WriteObjectToJson();
            _output.WriteLine(serializedTestCert);
            /**/
            var publicTestCert = testCertificate.GetOnlyPublic();
            var serializedPublicTestCert = publicTestCert.WriteObjectToJson();
            _output.WriteLine(serializedPublicTestCert);
            /**/
            Assert.True(testCertificate.Equals(publicTestCert));
            /**/
            var testCertCopy = serializedTestCert.ParseJsonToType<LightCertificate>();
            var publicTestCertCopy = serializedPublicTestCert.ParseJsonToType<LightCertificate>();
            Assert.True(testCertCopy.Equals(publicTestCertCopy));
            Assert.True(testCertificate.Equals(testCertCopy));
            Assert.True(publicTestCert.Equals(publicTestCertCopy));
        }
        [Fact]
        public void TestCreateSimpleSelfSignedCertificate()
        {
            var testCertificate = 
                LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa,
                    2048,
                    ELightCertificateEncryptType.Rsa,
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault,  
                    Guid.NewGuid(),
                    "TestCertificate",
                    Encoding.UTF8.GetBytes("TestPassword")
                );
            _output.WriteLine("{0}",testCertificate);
        }

        [Fact]
        public void TestCreateSimpleSignedCACertificate()
        {
            var testCertificate1 =
                LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa,
                    2048,
                    ELightCertificateEncryptType.Rsa,
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault, 
                    Guid.NewGuid(),
                    "TestCertificate1",
                    Encoding.UTF8.GetBytes("TestPassword1")
                );
            var testCertificate2 =
                LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa,
                    2048,
                    ELightCertificateEncryptType.Rsa,
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault, 
                    Guid.NewGuid(),
                    "TestCertificate2",
                    Encoding.UTF8.GetBytes("TestPassword2")
                );
            LightCertificatesHelper.SignCertificate(
                testCertificate2, 
                testCertificate1, 
                Encoding.UTF8.GetBytes("TestPassword1")
            );
            _output.WriteLine("{0}",testCertificate1.WriteObjectToJson());
            _output.WriteLine("{0}",testCertificate2.WriteObjectToJson());
        }

        [Fact]
        public void TestGuidXor()
        {
            var emissionMaskBytes = Guid.Parse("FFFFFFFF-FFFF-FFFF-FFFF-FF0000000000").ToByteArray();
            var emissionMaskEqualBytes = Guid.Parse("00000000-0000-0000-0000-0E0000000000").ToByteArray();
            var genIdBytes = Guid.NewGuid().ToByteArray();
            var resultBytes = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                resultBytes[i] = (byte)((emissionMaskBytes[i] & emissionMaskEqualBytes[i]) ^ ((0xff ^ emissionMaskBytes[i]) & genIdBytes[i]));
            }
            _output.WriteLine("{0}",new Guid(resultBytes));
        }

        public class A
        {
            public int Field1;
            public string Field2;
        }

        public class B : A
        {
            public Guid Field3 = Guid.NewGuid();
        }
        [Fact]
        public void TestCovariantSignedData()
        {
            var passBytes = Encoding.UTF8.GetBytes("TestPassword");
            var testCertificate =
                LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa, 
                    2048,
                    ELightCertificateEncryptType.Rsa, 
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault, 
                    Guid.NewGuid(),
                    "TestCertificate",
                    passBytes
                );
            var testB = new B()
            {
                Field1 = 1,
                Field2 = "sdasda",
                Field3 = Guid.NewGuid()
            };
            _output.WriteLine(testB.WriteObjectToJson());
            var testSignedData = new SignedData<B>(
                testB,
                testCertificate,
                passBytes
                );
            var signedData2 = testSignedData.To<A>();
            var testA = signedData2.GetValue();
            _output.WriteLine(testA.WriteObjectToJson());
        }

        [Fact]
        public void TestEncryptDecrypt()
        {
            var passBytes = Encoding.UTF8.GetBytes("TestPassword");
            var testCertificate =
                LightCertificatesHelper.GenerateSelfSignedCertificate(
                    ELightCertificateSignType.Rsa,
                    2048,
                    ELightCertificateEncryptType.Rsa,
                    2048,
                    EPrivateKeysKeyDerivationFunction.ScryptDefault,
                    Guid.NewGuid(),
                    "TestCertificate",
                    passBytes
                );
            foreach (var n in new[] {1,2,3,5,10,16,32,48,64,63,65,191})
            {
                var originData = new byte[n];
                MiscFuncs.GetRandomBytes(originData);
                var encryptedData = testCertificate.EncryptData(originData);
                var originDataCopy = testCertificate.DecryptData(encryptedData, passBytes);
                Assert.Equal(originData.Length, originDataCopy.Length);
                Assert.Equal(originData, originDataCopy);
            }
            for (int i = 0; i < 10; i++)
            {
                var aesPair = AesKeyIvPair.GenAesKeyIvPair();
                var encryptedPair = LightCertificatesHelper.EncryptAesKeyIvPair(
                    aesPair,
                    testCertificate
                );
                var decryptedPair = LightCertificatesHelper.DecryptAesKeyIvPair(
                    encryptedPair,
                    testCertificate,
                    passBytes
                );
                Assert.Equal(
                    aesPair.WriteObjectToJson(),
                    decryptedPair.WriteObjectToJson()
                );
            }
        }
        [Fact]
        public void TestGuidGen()
        {
            var g1 = Guid.NewGuid();
            _output.WriteLine($"{g1}");
            var g1Bytes = g1.ToByteArray();
            _output.WriteLine(MiscFuncs.ToBinaryString(g1Bytes));
            g1Bytes[0] = 0;
            g1Bytes[2] = 0;
            var g2 = new Guid(g1Bytes);
            _output.WriteLine($"{g2}");
        }
    }
}
