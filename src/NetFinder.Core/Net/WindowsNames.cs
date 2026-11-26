namespace NetFinder.Core.Net;

public static class WindowsNames
{
    /// <summary>
    /// "almada.local\admin" → ALMADA\admin, admin@almada.local, almada.local\admin. Logging in to a PC by its IP address
    /// uses NTLM, which wants the short (NetBIOS) domain name or the user@domain form; the DNS name before the backslash often fails.
    /// </summary>
    public static List<string> UserSpellings(string user, string? netbiosDomainHint = null)
    {
        var res = new List<string>();
        void Add(string u) { if (!res.Contains(u, StringComparer.OrdinalIgnoreCase)) res.Add(u); }
        var hint = netbiosDomainHint?.Trim().ToUpperInvariant();
        if (hint is "WORKGROUP" or "" || hint?.Contains('.') == true) hint = null;
        var bs = user.IndexOf('\\');
        var at = user.LastIndexOf('@');
        if (bs > 0 && bs < user.Length - 1)
        {
            string dom = user[..bs], name = user[(bs + 1)..];
            if (dom.Contains('.'))
            {
                var shortDom = dom.Split('.')[0].ToUpperInvariant();
                if (hint != null && hint != shortDom) Add($"{hint}\\{name}");
                Add($"{shortDom}\\{name}");
                Add($"{name}@{dom}");
            }
            Add(user);
        }
        else if (at > 0 && at < user.Length - 1 && bs < 0)
        {
            string name = user[..at], dom = user[(at + 1)..];
            Add(user);
            if (dom.Contains('.')) Add($"{(hint ?? dom.Split('.')[0].ToUpperInvariant())}\\{name}");
        }
        else Add(user);
        return res;
    }
}
