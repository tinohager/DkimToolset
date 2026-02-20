using DkimToolset;

Console.WriteLine("DkimToolset");
Console.WriteLine("-----------------------------------------");

var dkims = new string[]
{
    "v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMBe7mWbuirQNM7FLN9MEPLZquGCdNUq8EZMPEHWudxWVpQ0Gbgkq5CXJkqubPCrplFXjSQWT9ASj7A1hh7I17kCAwEAAQ==",
    "v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKVkxerC5fDCyhSkvPgeh0jEEV3+rxqxYATGbpgsQeIlhI15keYO7KoixpyEV3DcLZdBlOIqeLOUt0O7CvOpG9kCAwEAAQ==",
};

var scanner = new DkimSecurityScanner();
var compromisedKeys = scanner.ScanForSharedPrimes(dkims);

if (compromisedKeys.Count > 0)
{
    Console.WriteLine($"{compromisedKeys.Count} compromised Keys detected!");
    foreach (var key in compromisedKeys)
    {
        Console.WriteLine($"Index {key.Index}: factorized! (Bitlength: {key.BitLength})");
    }
}
else
{
    Console.WriteLine("No shared prime numbers found.");
}

Console.WriteLine("");
Console.WriteLine("-----------------------------------------");
Console.WriteLine("");

DkimRsaKeyHelper.GenerateLegacyExponentKey();
Console.WriteLine("-----------------------------------------");
DkimRsaKeyHelper.GenerateVulnerableSharedPrimeKey();