using System.Text.Json;
using Sentinel.Core.Users;
using Xunit;

namespace Sentinel.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void CreateAndVerify_Works()
    {
        var hash = PasswordHasher.CreateHash("MeinSicheresPasswort123!");
        Assert.True(PasswordHasher.Verify("MeinSicheresPasswort123!", hash));
    }

    [Fact]
    public void WrongPassword_Fails()
    {
        var hash = PasswordHasher.CreateHash("Richtig");
        Assert.False(PasswordHasher.Verify("Falsch", hash));
    }

    [Fact]
    public void SaltIsUnique()
    {
        var a = PasswordHasher.CreateHash("same");
        var b = PasswordHasher.CreateHash("same");
        Assert.NotEqual(Convert.ToBase64String(a.Salt), Convert.ToBase64String(b.Salt));
        Assert.NotEqual(Convert.ToBase64String(a.Hash), Convert.ToBase64String(b.Hash));
    }

    [Fact]
    public void DefaultIterationsAreStrong()
    {
        Assert.True(PasswordHasher.DefaultIterations >= 100_000);
    }

    [Fact]
    public void EmptyPassword_Fails()
    {
        Assert.Throws<ArgumentNullException>(() => PasswordHasher.CreateHash(null!));
        var hash = PasswordHasher.CreateHash("x");
        Assert.Throws<ArgumentNullException>(() => PasswordHasher.Verify(null!, hash));
    }

    [Theory]
    [InlineData("12345")]
    [InlineData("passwort")]
    [InlineData("abc")]
    [InlineData("aaaa")]
    public void WeakPasswords_ScoreLow(string password)
    {
        var strength = PasswordHasher.ScoreStrength(password);
        Assert.True(strength.Score < 40, $"{password} sollte schwach bewertet werden, war {strength.Score}");
        Assert.NotEmpty(strength.ImprovementHints);
    }

    [Fact]
    public void StrongPassword_ScoresHigh()
    {
        var strength = PasswordHasher.ScoreStrength("Xq7$mK2pLz9#Wn4V");
        Assert.True(strength.Score >= 80);
    }

    [Fact]
    public void CommonWordIsFlagged()
    {
        var strength = PasswordHasher.ScoreStrength("Sommer2026!!");
        Assert.Contains(strength.ImprovementHints, h => h.Contains("häufiges Wort"));
    }

    [Fact]
    public void SequenceIsFlagged()
    {
        var strength = PasswordHasher.ScoreStrength("abcdefgh");
        Assert.Contains(strength.ImprovementHints, h => h.Contains("Tastatur- oder Zahlenfolge"));
    }

    [Fact]
    public void EmptyPassword_ZeroStrength()
    {
        var strength = PasswordHasher.ScoreStrength("");
        Assert.Equal(0, strength.Score);
    }
}

public class UserManagerTests
{
    private static string TempPath() =>
        Path.Combine(Path.GetTempPath(), $"sentinel_user_{Guid.NewGuid():N}.json");

    [Fact]
    public void CreateFirstUser_ThenLogin_Works()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var user = manager.CreateFirstUser("Felix", "SicheresPasswort1!");

            Assert.Equal(UserRole.Admin, user.Role);
            Assert.True(manager.HasAdmin);

            var result = manager.Login("Felix", "SicheresPasswort1!");
            Assert.Equal(AuthResult.Success, result);
            Assert.NotNull(manager.CurrentUser);
            Assert.Equal("Felix", manager.CurrentUser!.DisplayName);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void AddUser_MultipleUsersWork()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            manager.CreateFirstUser("Admin", "AdminPasswort1!");
            manager.AddUser("Mareike", "NutzerPasswort2!", UserRole.User);

            Assert.Equal(2, manager.Users.Count);

            Assert.Equal(AuthResult.Success, manager.Login("Admin", "AdminPasswort1!"));
            Assert.True(manager.CurrentUser!.IsAdmin);

            Assert.Equal(AuthResult.Success, manager.Login("Mareike", "NutzerPasswort2!"));
            Assert.False(manager.CurrentUser!.IsAdmin);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void DuplicateName_Rejected()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            manager.CreateFirstUser("Felix", "Passwort1!");
            Assert.Throws<InvalidOperationException>(() => manager.AddUser("felix", "Passwort2!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void WrongPassword_FailsAndCounts()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            manager.CreateFirstUser("Felix", "Richtig1!");

            var result = manager.Login("Felix", "Falsch1!");

            Assert.Equal(AuthResult.WrongPassword, result);
            Assert.True(manager.RemainingLockout(manager.Users[0].Id) is null); // noch nicht gesperrt
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void FiveFailedAttempts_LocksUser()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            manager.CreateFirstUser("Felix", "Richtig1!");

            for (int i = 0; i < 5; i++)
                manager.Login("Felix", "Falsch1!");

            var result = manager.Login("Felix", "Richtig1!");
            Assert.Equal(AuthResult.UserLocked, result);
            Assert.NotNull(manager.RemainingLockout(manager.Users[0].Id));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void LoginWithoutUser_ReturnsNoUser()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            Assert.Equal(AuthResult.NoUser, manager.Login("irgendwas", "irgendwas"));
            Assert.False(manager.HasUsers);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ChangePassword_Works()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var user = manager.CreateFirstUser("Felix", "Alt1!");

            Assert.True(manager.ChangePassword(user.Id, "Alt1!", "Neu2!"));
            Assert.Equal(AuthResult.Success, manager.Login("Felix", "Neu2!"));
            Assert.NotEqual(AuthResult.Success, manager.Login("Felix", "Alt1!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ChangePassword_WrongOldPassword_Fails()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var user = manager.CreateFirstUser("Felix", "Alt1!");

            Assert.False(manager.ChangePassword(user.Id, "Falsch", "Neu2!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void LastAdmin_CannotBeRemoved()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var admin = manager.CreateFirstUser("Admin", "Passwort1!");

            Assert.Throws<InvalidOperationException>(
                () => manager.RemoveUser(admin.Id, "Passwort1!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void LastAdmin_CannotBeDemoted()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var admin = manager.CreateFirstUser("Admin", "Passwort1!");

            Assert.Throws<InvalidOperationException>(
                () => manager.ChangeRole(admin.Id, UserRole.User));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void RemoveUser_RequiresAdminPassword()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            var admin = manager.CreateFirstUser("Admin", "Passwort1!");
            var user = manager.AddUser("User", "Passwort2!");

            Assert.False(manager.RemoveUser(user.Id, "falsch"));
            Assert.True(manager.RemoveUser(user.Id, "Passwort1!"));
            Assert.Single(manager.Users);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void ResetPassword_AdminAction()
    {
        var path = TempPath();
        try
        {
            var manager = new UserManager(path);
            manager.CreateFirstUser("Admin", "Passwort1!");
            var user = manager.AddUser("User", "Passwort2!");

            Assert.True(manager.ResetPassword(user.Id, "Neues3!"));
            Assert.Equal(AuthResult.Success, manager.Login("User", "Neues3!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Reload_PersistsUsers()
    {
        var path = TempPath();
        try
        {
            var manager1 = new UserManager(path);
            manager1.CreateFirstUser("Admin", "Passwort1!");
            manager1.AddUser("User", "Passwort2!");

            var manager2 = new UserManager(path);
            Assert.Equal(2, manager2.Users.Count);
            Assert.True(manager2.HasAdmin);
            Assert.Equal(AuthResult.Success, manager2.Login("Admin", "Passwort1!"));
            Assert.Equal(AuthResult.Success, manager2.Login("User", "Passwort2!"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void LegacyFormat_MigratesToAdmin()
    {
        var path = TempPath();
        try
        {
            // Altes Single-User-Format simulieren (User als JSON-String, wie die alte Save() es schrieb)
            var oldAccount = new UserAccount
            {
                DisplayName = "AlterNutzer",
                Password = PasswordHasher.CreateHash("Passwort1!")
            };
            File.WriteAllText(path, JsonSerializer.Serialize(new { user = oldAccount.ToJson() }));

            var manager = new UserManager(path);
            Assert.Single(manager.Users);
            Assert.True(manager.Users[0].IsAdmin); // Legacy-Nutzer wird Admin
            Assert.Equal(AuthResult.Success, manager.Login("AlterNutzer", "Passwort1!"));

            // Neues Format geschrieben?
            var content = File.ReadAllText(path);
            Assert.Contains("\"users\"", content);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void CorruptFile_NoCrash()
    {
        var path = TempPath();
        try
        {
            File.WriteAllText(path, "kein json{{{");
            var manager = new UserManager(path);
            Assert.False(manager.HasUsers);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
