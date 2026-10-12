using Sentinel.Core.Reporting;
using Sentinel.Core.Scoring;
using Xunit;

namespace Sentinel.Tests;

public class HistoryStoreTests
{
    private static SecurityScore Score(int value, int passed = 1, int warnings = 0, int failed = 0) =>
        new()
        {
            Value = value,
            Grade = value >= 80 ? ScoreGrade.Gut : ScoreGrade.Verbesserungsbedarf,
            Passed = passed, Warnings = warnings, Failed = failed,
            Graded = passed + warnings + failed
        };

    [Fact]
    public void AppendAndLoad_RoundTrips()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel_hist_{Guid.NewGuid():N}.json");
        try
        {
            var store = new HistoryStore(path);
            store.Append(Score(75, passed: 3, warnings: 1));
            store.Append(Score(90, passed: 4));

            var entries = store.Load();
            Assert.Equal(2, entries.Count);
            Assert.Equal(75, entries[0].Score);
            Assert.Equal(90, entries[1].Score);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void LoadMissingFile_ReturnsEmpty()
    {
        var store = new HistoryStore(Path.Combine(Path.GetTempPath(), $"nope_{Guid.NewGuid():N}.json"));
        Assert.Empty(store.Load());
    }

    [Fact]
    public void Clear_RemovesFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel_clear_{Guid.NewGuid():N}.json");
        var store = new HistoryStore(path);
        store.Append(Score(50));
        store.Clear();

        Assert.False(File.Exists(path));
        Assert.Empty(store.Load());
    }

    [Fact]
    public void CorruptFile_DoesNotThrow()
    {
        var path = Path.Combine(Path.GetTempPath(), $"sentinel_bad_{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, "kein json{{{");
            var store = new HistoryStore(path);
            Assert.Empty(store.Load());
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
