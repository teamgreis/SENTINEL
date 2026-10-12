using Sentinel.Core.Users;
using Xunit;

namespace Sentinel.Tests;

public class BackupKeyTests
{
    [Fact]
    public void GenerateCode_HasCorrectFormat()
    {
        var code = BackupKeyGenerator.GenerateCode();

        // XXXX-XXXX-XXXX-XXXX
        Assert.Equal(19, code.Length);
        Assert.Equal('-', code[4]);
        Assert.Equal('-', code[9]);
        Assert.Equal('-', code[14]);
        Assert.All(code.Where(c => c != '-'), c => Assert.True(char.IsLetterOrDigit(c), $"{c} sollte alphanumerisch sein"));
    }

    [Fact]
    public void GenerateCode_IsUnique()
    {
        var codes = Enumerable.Range(0, 100).Select(_ => BackupKeyGenerator.GenerateCode()).ToHashSet();
        Assert.Equal(100, codes.Count);
    }

    [Fact]
    public void Normalize_HandlesBothFormats()
    {
        string withDashes = "ABCD-EFGH-IJKL-MNOP";
        string withoutDashes = "ABCDEFGHIJKLMNOP";

        Assert.Equal(withDashes, BackupKeyGenerator.Normalize(withoutDashes));
        Assert.Equal(withDashes, BackupKeyGenerator.Normalize(withDashes));
        Assert.Equal(withDashes, BackupKeyGenerator.Normalize("abcd-efgh-ijkl-mnop"));
        Assert.Equal(withDashes, BackupKeyGenerator.Normalize("abcdefgh ijkl mnop"));
    }

    [Fact]
    public void Matches_TimeConstantComparison()
    {
        Assert.True(BackupKeyGenerator.Matches("ABCD-EFGH-IJKL-MNOP", "abcd-efgh-ijkl-mnop"));
        Assert.True(BackupKeyGenerator.Matches("ABCDEFGHIJKLMNOP", "ABCD-EFGH-IJKL-MNOP"));
        Assert.False(BackupKeyGenerator.Matches("ABCD-EFGH-IJKL-MNOP", "ABCD-EFGH-IJKL-MNPX"));
        Assert.False(BackupKeyGenerator.Matches("ABCD-EFGH-IJKL-MNOP", ""));
        Assert.False(BackupKeyGenerator.Matches("", "ABCD-EFGH-IJKL-MNOP"));
    }

    [Fact]
    public void Store_CreateAndConsume()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sentinel_bk_{Guid.NewGuid():N}.json");
        try
        {
            var store = new BackupKeyStore(path);
            var codes = store.CreateForUser("user-1", 2);

            Assert.Equal(2, codes.Count);
            Assert.Equal(2, store.RemainingForUser("user-1"));

            // Falscher Code wird abgelehnt
            Assert.False(store.TryConsume("user-1", "XXXX-XXXX-XXXX-XXXX"));
            Assert.Equal(2, store.RemainingForUser("user-1"));

            // Richtiger Code wird akzeptiert und verbraucht
            Assert.True(store.TryConsume("user-1", codes[0]));
            Assert.Equal(1, store.RemainingForUser("user-1"));

            // Verbrauchter Code gilt nicht mehr
            Assert.False(store.TryConsume("user-1", codes[0]));

            // Zweiter Code geht noch
            Assert.True(store.TryConsume("user-1", codes[1]));
            Assert.Equal(0, store.RemainingForUser("user-1"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Store_PersistsAcrossInstances()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sentinel_bk_{Guid.NewGuid():N}.json");
        try
        {
            var store1 = new BackupKeyStore(path);
            var codes = store1.CreateForUser("user-1", 2);

            var store2 = new BackupKeyStore(path);
            Assert.Equal(2, store2.RemainingForUser("user-1"));
            Assert.True(store2.VerifyForUser("user-1", codes[0]));
            Assert.False(store2.VerifyForUser("user-1", "XXXX-XXXX-XXXX-XXXX"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Store_NeverStoresPlaintextCode()
    {
        string path = Path.Combine(Path.GetTempPath(), $"sentinel_bk_{Guid.NewGuid():N}.json");
        try
        {
            var store = new BackupKeyStore(path);
            var codes = store.CreateForUser("user-1", 2);

            string content = File.ReadAllText(path);
            Assert.DoesNotContain(codes[0], content);
            Assert.DoesNotContain(codes[1], content);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
