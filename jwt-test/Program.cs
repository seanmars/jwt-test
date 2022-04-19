using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;

var token = GetToken();
Console.WriteLine(token);


string GetToken()
{
    var dsa = GetEcDsa();
    return CreateJwt(dsa, "key-id", "issuer-id");
}

ECDsa GetEcDsa()
{
    using TextReader reader = System.IO.File.OpenText("AuthKey_xxxxx.p8");
    var ecPrivateKeyParameters =
        (ECPrivateKeyParameters)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();

    var q = ecPrivateKeyParameters.Parameters.G.Multiply(ecPrivateKeyParameters.D).Normalize();
    var qx = q.AffineXCoord.GetEncoded();
    var qy = q.AffineYCoord.GetEncoded();
    var d = ecPrivateKeyParameters.D.ToByteArrayUnsigned();

    // Convert the BouncyCastle key to a Native Key.
    var msEcp = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = { X = qx, Y = qy }, D = d };
    return ECDsa.Create(msEcp);
}

string CreateJwt(ECDsa key, string keyId, string issuer)
{
    var securityKey = new ECDsaSecurityKey(key) { KeyId = keyId };
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

    var descriptor = new SecurityTokenDescriptor
    {
        IssuedAt = DateTime.Now,
        Expires = DateTime.Now.AddMinutes(10),
        Issuer = issuer,
        Audience = "appstoreconnect-v1",
        SigningCredentials = credentials,
    };

    var handler = new JwtSecurityTokenHandler();
    var encodedToken = handler.CreateEncodedJwt(descriptor);
    var st = handler.CreateJwtSecurityToken(descriptor);

    return st.EncodedHeader + "." + st.EncodedPayload + "." + st.RawSignature;
}