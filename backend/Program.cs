using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ---------- 配置 ----------
var port = Environment.GetEnvironmentVariable("PORT") ?? "3000";
var adminToken = Environment.GetEnvironmentVariable("ADMIN_TOKEN") ?? "admin123";
var secret = Environment.GetEnvironmentVariable("SECRET") ?? "zhongke-secret-2026";

var current = Directory.GetCurrentDirectory();
var publicDir = Environment.GetEnvironmentVariable("PUBLIC_DIR");
if (string.IsNullOrWhiteSpace(publicDir))
{
    if (File.Exists(Path.Combine(current, "index.html"))) publicDir = current;
    else if (File.Exists(Path.Combine(current, "..", "index.html"))) publicDir = Path.GetFullPath(Path.Combine(current, ".."));
    else publicDir = current;
}
publicDir = Path.GetFullPath(publicDir);

var dataDir = Path.Combine(publicDir, "data");
Directory.CreateDirectory(dataDir);
string FileOf(string name) { var p = Path.Combine(dataDir, name); if (!File.Exists(p)) File.WriteAllText(p, "[]"); return p; }
var inquiriesFile = FileOf("inquiries.json");
var usersFile = FileOf("users.json");
var newsFile = FileOf("news.json");
var casesFile = FileOf("cases.json");
var productsFile = FileOf("products.json");

var jsonOpts = new JsonSerializerOptions
{
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    WriteIndented = true
};

// ---------- 存储（文件 + 锁） ----------
var storeLock = new object();

T? ReadJson<T>(string file) where T : class
{
    lock (storeLock)
    {
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(file), jsonOpts); }
        catch { return null; }
    }
}
void WriteJson<T>(string file, T value) where T : class
{
    lock (storeLock)
    {
        File.WriteAllText(file, JsonSerializer.Serialize(value, jsonOpts));
    }
}
async Task<T?> ReadBody<T>(HttpContext ctx) where T : class
{
    using var reader = new StreamReader(ctx.Request.Body);
    var raw = await reader.ReadToEndAsync();
    try { return JsonSerializer.Deserialize<T>(raw, jsonOpts); }
    catch { return null; }
}

// ---------- 鉴权辅助 ----------
bool RequireAdmin(HttpContext ctx) => ctx.Request.Query["key"].ToString() == adminToken;
string GenId() => DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString("x") + Guid.NewGuid().ToString("N")[..6];

// ---------- 图形验证码（内存存储，5 分钟有效，一次性） ----------
var captchaStore = new Dictionary<string, (string Code, DateTime Exp)>();

// ---------- 密码哈希 (PBKDF2) ----------
(string hash, string salt) HashPassword(string password)
{
    var saltBytes = new byte[16];
    using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(saltBytes);
    using var pbkdf = new Rfc2898DeriveBytes(password, saltBytes, 100_000, HashAlgorithmName.SHA256);
    return (Convert.ToBase64String(pbkdf.GetBytes(32)), Convert.ToBase64String(saltBytes));
}
bool VerifyPassword(string password, string hash, string salt)
{
    var saltBytes = Convert.FromBase64String(salt);
    using var pbkdf = new Rfc2898DeriveBytes(password, saltBytes, 100_000, HashAlgorithmName.SHA256);
    var hashBytes = pbkdf.GetBytes(32);
    return CryptographicOperations.FixedTimeEquals(hashBytes, Convert.FromBase64String(hash));
}

// ---------- Token（HMAC 签名，无状态） ----------
string Sign(string payload)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload)));
}
string CreateToken(string uid)
{
    var payloadJson = JsonSerializer.Serialize(new TokenPayload(uid, DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds()), jsonOpts);
    var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson));
    return payload + "." + Sign(payload);
}
bool TryGetUserFromToken(HttpContext ctx, out string uid)
{
    uid = "";
    var auth = ctx.Request.Headers["Authorization"].ToString();
    if (!auth.StartsWith("Bearer ", StringComparison.Ordinal)) return false;
    var parts = auth["Bearer ".Length..].Split('.');
    if (parts.Length != 2) return false;
    var expected = Encoding.UTF8.GetBytes(Sign(parts[0]));
    var given = Encoding.UTF8.GetBytes(parts[1]);
    if (expected.Length != given.Length || !CryptographicOperations.FixedTimeEquals(expected, given)) return false;
    try
    {
        var p = JsonSerializer.Deserialize<TokenPayload>(Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])), jsonOpts);
        if (p == null || p.Exp < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return false;
        uid = p.Uid;
        return true;
    }
    catch { return false; }
}
PublicUser ToPublic(User u) => new() { Id = u.Id, Name = u.Name, Phone = u.Phone, CreatedAt = u.CreatedAt };

// ===================================================================
// 账号：注册 / 登录 / 当前用户
// ===================================================================
app.MapPost("/api/register", async (HttpContext ctx) =>
{
    var d = await ReadBody<RegisterDto>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var name = (d.Name ?? "").Trim();
    var phone = (d.Phone ?? "").Trim();
    var pwd = d.Password ?? "";
    var confirm = d.Confirm ?? "";
    if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(phone) || string.IsNullOrEmpty(pwd))
        return Results.BadRequest(new { ok = false, msg = "请填写姓名、手机号与密码" });
    if (!Regex.IsMatch(phone, @"^1[3-9]\d{9}$"))
        return Results.BadRequest(new { ok = false, msg = "手机号格式不正确" });
    if (pwd.Length < 6 || pwd.Length > 20)
        return Results.BadRequest(new { ok = false, msg = "密码需为 6-20 位" });
    if (pwd != confirm)
        return Results.BadRequest(new { ok = false, msg = "两次输入的密码不一致" });

    var users = ReadJson<List<User>>(usersFile) ?? new();
    if (users.Any(u => u.Phone == phone))
        return Results.BadRequest(new { ok = false, msg = "该手机号已注册" });

    var (hash, salt) = HashPassword(pwd);
    var user = new User
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = name,
        Phone = phone,
        PasswordHash = hash,
        PasswordSalt = salt,
        CreatedAt = DateTime.UtcNow.ToString("o")
    };
    users.Add(user);
    WriteJson(usersFile, users);

    var token = CreateToken(user.Id);
    return Results.Ok(new { ok = true, msg = "注册成功", token, user = ToPublic(user) });
});

// ===================================================================
// 图形验证码
// ===================================================================
app.MapGet("/api/captcha", () =>
{
    const string chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    var code = new string(Enumerable.Range(0, 4).Select(_ => chars[Random.Shared.Next(chars.Length)]).ToArray());
    var id = Guid.NewGuid().ToString("N");
    lock (storeLock)
    {
        foreach (var k in captchaStore.Where(kv => kv.Value.Exp < DateTime.UtcNow).Select(kv => kv.Key).ToList())
            captchaStore.Remove(k);
        captchaStore[id] = (code, DateTime.UtcNow.AddMinutes(5));
    }

    string[] palette = { "#1a5fc4", "#c0392b", "#188038", "#7b3ff2", "#b26a00" };
    var rnd = Random.Shared;
    var text = string.Concat(code.Select((c, i) =>
    {
        var x = 20 + i * 27;
        var y = 33 + rnd.Next(-4, 5);
        var rot = rnd.Next(-24, 25);
        var col = palette[rnd.Next(palette.Length)];
        return $"<text x=\"{x}\" y=\"{y}\" font-size=\"30\" font-family=\"Arial, sans-serif\" font-weight=\"bold\" fill=\"{col}\" transform=\"rotate({rot} {x} {y})\">{c}</text>";
    }));
    var lines = string.Concat(Enumerable.Range(0, 3).Select(_ =>
        $"<line x1=\"{rnd.Next(0, 130)}\" y1=\"{rnd.Next(0, 50)}\" x2=\"{rnd.Next(0, 130)}\" y2=\"{rnd.Next(0, 50)}\" stroke=\"#b6c2d2\" stroke-width=\"1.4\" opacity=\"0.7\"/>"));
    var dots = string.Concat(Enumerable.Range(0, 18).Select(_ =>
        $"<circle cx=\"{rnd.Next(0, 130)}\" cy=\"{rnd.Next(0, 48)}\" r=\"1\" fill=\"#9fb0c4\" opacity=\"0.6\"/>"));
    var svg = $"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"130\" height=\"48\" viewBox=\"0 0 130 48\"><rect width=\"130\" height=\"48\" rx=\"8\" fill=\"#f2f5f9\"/>{dots}{lines}{text}</svg>";
    return Results.Ok(new { ok = true, id, svg });
});

app.MapPost("/api/login", async (HttpContext ctx) =>
{
    var d = await ReadBody<LoginDto>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var account = (d.Account ?? "").Trim();
    var pwd = d.Password ?? "";
    if (string.IsNullOrEmpty(account) || string.IsNullOrEmpty(pwd))
        return Results.BadRequest(new { ok = false, msg = "请输入账号和密码" });

    // 图形验证码校验（一次性，防止暴力破解）
    var capId = (d.CaptchaId ?? "").Trim();
    var capCode = (d.Captcha ?? "").Trim().ToUpperInvariant();
    lock (storeLock)
    {
        if (!captchaStore.TryGetValue(capId, out var cap) || cap.Exp < DateTime.UtcNow)
            return Results.BadRequest(new { ok = false, msg = "验证码已过期，请点击图片刷新后重试" });
        captchaStore.Remove(capId);
        if (cap.Code != capCode)
            return Results.BadRequest(new { ok = false, msg = "验证码不正确" });
    }

    var users = ReadJson<List<User>>(usersFile) ?? new();
    var user = users.FirstOrDefault(u => u.Phone == account);
    if (user == null || !VerifyPassword(pwd, user.PasswordHash, user.PasswordSalt))
        return Results.BadRequest(new { ok = false, msg = "账号或密码错误" });

    var token = CreateToken(user.Id);
    return Results.Ok(new { ok = true, msg = "登录成功", token, user = ToPublic(user) });
});

app.MapGet("/api/me", (HttpContext ctx) =>
{
    if (!TryGetUserFromToken(ctx, out var uid))
        return Results.Json(new { ok = false, msg = "未登录" }, statusCode: 401);
    var users = ReadJson<List<User>>(usersFile) ?? new();
    var user = users.FirstOrDefault(u => u.Id == uid);
    if (user == null) return Results.Json(new { ok = false, msg = "用户不存在" }, statusCode: 401);
    return Results.Ok(new { ok = true, user = ToPublic(user) });
});

// ===================================================================
// 需求提交（公开创建） + 后台列表/编辑/删除
// ===================================================================
app.MapPost("/api/inquiry", async (HttpContext ctx) =>
{
    if (ctx.Request.ContentLength is > 1_000_000) return Results.StatusCode(413);
    var d = await ReadBody<Inquiry>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var name = (d.Name ?? "").Trim();
    var phone = (d.Phone ?? "").Trim();
    var message = (d.Message ?? "").Trim();
    if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(phone) || string.IsNullOrEmpty(message))
        return Results.BadRequest(new { ok = false, msg = "请填写姓名、电话和检测需求" });
    if (!Regex.IsMatch(phone, @"^[\d\-+\s()]{6,20}$"))
        return Results.BadRequest(new { ok = false, msg = "电话号码格式不正确" });
    if (!string.IsNullOrWhiteSpace(d.Email) && !Regex.IsMatch(d.Email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
        return Results.BadRequest(new { ok = false, msg = "邮箱格式不正确" });

    var item = new Inquiry
    {
        Id = GenId(),
        Name = name,
        Phone = phone,
        Company = (d.Company ?? "").Trim(),
        Email = (d.Email ?? "").Trim(),
        Category = (d.Category ?? "").Trim(),
        Message = message,
        Status = "待跟进",
        Ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "",
        CreatedAt = DateTime.UtcNow.ToString("o")
    };
    var list = ReadJson<List<Inquiry>>(inquiriesFile) ?? new();
    list.Insert(0, item);
    WriteJson(inquiriesFile, list);
    return Results.Ok(new { ok = true, msg = "提交成功，工程师会尽快联系您" });
});

app.MapGet("/api/inquiries", (HttpContext ctx) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var list = ReadJson<List<Inquiry>>(inquiriesFile) ?? new();
    return Results.Ok(new { ok = true, total = list.Count, items = list });
});

app.MapPut("/api/admin/inquiries/{id}", async (HttpContext ctx, string id) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var d = await ReadBody<Inquiry>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var list = ReadJson<List<Inquiry>>(inquiriesFile) ?? new();
    var idx = list.FindIndex(x => x.Id == id);
    if (idx < 0) return Results.NotFound(new { ok = false, msg = "记录不存在" });
    d.Id = id;
    if (string.IsNullOrEmpty(d.CreatedAt)) d.CreatedAt = list[idx].CreatedAt;
    if (string.IsNullOrEmpty(d.Ip)) d.Ip = list[idx].Ip;
    if (string.IsNullOrEmpty(d.Status)) d.Status = list[idx].Status;
    list[idx] = d;
    WriteJson(inquiriesFile, list);
    return Results.Ok(new { ok = true, msg = "更新成功" });
});

app.MapDelete("/api/admin/inquiries/{id}", (HttpContext ctx, string id) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var list = ReadJson<List<Inquiry>>(inquiriesFile) ?? new();
    var removed = list.RemoveAll(x => x.Id == id);
    if (removed == 0) return Results.NotFound(new { ok = false, msg = "记录不存在" });
    WriteJson(inquiriesFile, list);
    return Results.Ok(new { ok = true, msg = "删除成功" });
});

// ===================================================================
// 后台：注册用户 列表 / 新建 / 编辑(可重置密码) / 删除
// ===================================================================
app.MapGet("/api/users", (HttpContext ctx) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var list = ReadJson<List<User>>(usersFile) ?? new();
    return Results.Ok(new { ok = true, total = list.Count, items = list.Select(ToPublic).ToList() });
});

// 管理员新建用户
app.MapPost("/api/admin/users", async (HttpContext ctx) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var d = await ReadBody<RegisterDto>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var name = (d.Name ?? "").Trim();
    var phone = (d.Phone ?? "").Trim();
    var pwd = d.Password ?? "";
    if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(phone) || string.IsNullOrEmpty(pwd))
        return Results.BadRequest(new { ok = false, msg = "请填写姓名、手机号与密码" });
    if (!Regex.IsMatch(phone, @"^1[3-9]\d{9}$"))
        return Results.BadRequest(new { ok = false, msg = "手机号格式不正确" });
    if (pwd.Length < 6 || pwd.Length > 20)
        return Results.BadRequest(new { ok = false, msg = "密码需为 6-20 位" });

    var users = ReadJson<List<User>>(usersFile) ?? new();
    if (users.Any(u => u.Phone == phone))
        return Results.BadRequest(new { ok = false, msg = "该手机号已注册" });

    var (hash, salt) = HashPassword(pwd);
    var user = new User
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = name,
        Phone = phone,
        PasswordHash = hash,
        PasswordSalt = salt,
        CreatedAt = DateTime.UtcNow.ToString("o")
    };
    users.Add(user);
    WriteJson(usersFile, users);
    return Results.Ok(new { ok = true, msg = "创建成功" });
});

app.MapPut("/api/admin/users/{id}", async (HttpContext ctx, string id) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var d = await ReadBody<RegisterDto>(ctx);
    if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
    var list = ReadJson<List<User>>(usersFile) ?? new();
    var u = list.FirstOrDefault(x => x.Id == id);
    if (u == null) return Results.NotFound(new { ok = false, msg = "用户不存在" });
    if (!string.IsNullOrWhiteSpace(d.Name)) u.Name = d.Name.Trim();
    if (!string.IsNullOrWhiteSpace(d.Phone))
    {
        var phone = d.Phone.Trim();
        if (!Regex.IsMatch(phone, @"^1[3-9]\d{9}$"))
            return Results.BadRequest(new { ok = false, msg = "手机号格式不正确" });
        if (list.Any(x => x.Id != id && x.Phone == phone))
            return Results.BadRequest(new { ok = false, msg = "该手机号已被其他用户使用" });
        u.Phone = phone;
    }
    if (!string.IsNullOrWhiteSpace(d.Password))
    {
        var pwd = d.Password;
        if (pwd.Length < 6 || pwd.Length > 20)
            return Results.BadRequest(new { ok = false, msg = "密码需为 6-20 位" });
        var (hash, salt) = HashPassword(pwd);
        u.PasswordHash = hash;
        u.PasswordSalt = salt;
    }
    WriteJson(usersFile, list);
    return Results.Ok(new { ok = true, msg = "更新成功" });
});

app.MapDelete("/api/admin/users/{id}", (HttpContext ctx, string id) =>
{
    if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
    var list = ReadJson<List<User>>(usersFile) ?? new();
    var removed = list.RemoveAll(x => x.Id == id);
    if (removed == 0) return Results.NotFound(new { ok = false, msg = "用户不存在" });
    WriteJson(usersFile, list);
    return Results.Ok(new { ok = true, msg = "删除成功" });
});

// ===================================================================
// 内容（新闻/案例/产品）：公开列表 + 后台 增/改/删
// ===================================================================
void RegisterContentCrud<T>(string name, string file) where T : class, new()
{
    app.MapGet($"/api/{name}", () =>
    {
        var list = ReadJson<List<T>>(file) ?? new();
        return Results.Ok(new { ok = true, items = list });
    });

    app.MapPost($"/api/admin/{name}", async (HttpContext ctx) =>
    {
        if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
        var d = await ReadBody<T>(ctx);
        if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
        var list = ReadJson<List<T>>(file) ?? new();
        var prop = typeof(T).GetProperty("Id")!;
        if (string.IsNullOrWhiteSpace((string?)prop.GetValue(d))) prop.SetValue(d, GenId());
        list.Insert(0, d);
        WriteJson(file, list);
        return Results.Ok(new { ok = true, msg = "创建成功" });
    });

    app.MapPut($"/api/admin/{name}/{{id}}", async (HttpContext ctx, string id) =>
    {
        if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
        var d = await ReadBody<T>(ctx);
        if (d == null) return Results.BadRequest(new { ok = false, msg = "数据格式错误" });
        var list = ReadJson<List<T>>(file) ?? new();
        var prop = typeof(T).GetProperty("Id")!;
        var idx = list.FindIndex(x => (string?)prop.GetValue(x) == id);
        if (idx < 0) return Results.NotFound(new { ok = false, msg = "记录不存在" });
        prop.SetValue(d, id);
        list[idx] = d;
        WriteJson(file, list);
        return Results.Ok(new { ok = true, msg = "更新成功" });
    });

    app.MapDelete($"/api/admin/{name}/{{id}}", (HttpContext ctx, string id) =>
    {
        if (!RequireAdmin(ctx)) return Results.Json(new { ok = false, msg = "未授权" }, statusCode: 401);
        var list = ReadJson<List<T>>(file) ?? new();
        var prop = typeof(T).GetProperty("Id")!;
        var removed = list.RemoveAll(x => (string?)prop.GetValue(x) == id);
        if (removed == 0) return Results.NotFound(new { ok = false, msg = "记录不存在" });
        WriteJson(file, list);
        return Results.Ok(new { ok = true, msg = "删除成功" });
    });
}
RegisterContentCrud<NewsItem>("news", newsFile);
RegisterContentCrud<CaseItem>("cases", casesFile);
RegisterContentCrud<ProductItem>("products", productsFile);

// ===================================================================
// 后台页面
// ===================================================================
app.MapGet("/admin", (HttpContext ctx) =>
{
    var adminHtml = Path.Combine(publicDir, "admin.html");
    return File.Exists(adminHtml)
        ? Results.File(adminHtml, "text/html; charset=utf-8")
        : Results.NotFound();
});

// ===================================================================
// 静态资源
// ===================================================================
var allowedExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    ".html", ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".txt", ".json"
};
var blockedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "data", "bin", "obj", "properties"
};
var blockedExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    ".cs", ".csproj", ".dll", ".exe", ".config", ".user", ".sln"
};

app.MapGet("/{*url}", (string? url) =>
{
    var rel = string.IsNullOrEmpty(url) ? "index.html" : url!;
    var root = Path.GetFullPath(publicDir);
    var full = Path.GetFullPath(Path.Combine(publicDir, rel));

    if (full != root && !full.StartsWith(root + Path.DirectorySeparatorChar))
        return Results.StatusCode(403);

    var relDir = Path.GetRelativePath(root, full);
    foreach (var seg in relDir.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        if (blockedDirs.Contains(seg))
            return Results.StatusCode(403);

    if (Directory.Exists(full))
        full = Path.Combine(full, "index.html");

    if (!File.Exists(full))
        return Results.NotFound();

    var ext = Path.GetExtension(full).ToLowerInvariant();
    if (!allowedExt.Contains(ext) || blockedExt.Contains(ext))
        return Results.StatusCode(403);

    return Results.File(full, GetMime(ext));
});

// ==================== 启动 ====================
var urls = $"http://localhost:{port}";
Console.WriteLine("中科视界后端已启动 → " + urls);
Console.WriteLine("官网首页:  " + urls + "/");
Console.WriteLine("需求后台:  " + urls + "/admin  (口令: " + adminToken + ")");
Console.WriteLine("静态目录:  " + publicDir);

app.Run(urls);

// ---------- 辅助函数（顶层局部函数须位于类型声明之前） ----------
static string GetMime(string ext) => ext switch
{
    ".html" => "text/html; charset=utf-8",
    ".css" => "text/css; charset=utf-8",
    ".js" => "application/javascript; charset=utf-8",
    ".json" => "application/json; charset=utf-8",
    ".svg" => "image/svg+xml",
    ".png" => "image/png",
    ".jpg" or ".jpeg" => "image/jpeg",
    ".ico" => "image/x-icon",
    ".webp" => "image/webp",
    _ => "application/octet-stream"
};

// ---------- 模型 ----------
class User
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Phone { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public string CreatedAt { get; set; } = "";
}
class PublicUser
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Phone { get; set; } = "";
    public string CreatedAt { get; set; } = "";
}
class Inquiry
{
    public string? Id { get; set; }
    public string? Name { get; set; }
    public string? Phone { get; set; }
    public string? Company { get; set; }
    public string? Email { get; set; }
    public string? Category { get; set; }
    public string? Message { get; set; }
    public string? Status { get; set; }
    public string? Ip { get; set; }
    public string? CreatedAt { get; set; }
}
class NewsItem
{
    public string Id { get; set; } = "";
    public string Tag { get; set; } = "";
    public string Title { get; set; } = "";
    public string Desc { get; set; } = "";
    public string Date { get; set; } = "";
}
class Metric
{
    public string Value { get; set; } = "";
    public string Label { get; set; } = "";
}
class CaseItem
{
    public string Id { get; set; } = "";
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public string Desc { get; set; } = "";
    public List<Metric> Metrics { get; set; } = new();
    public string Icon { get; set; } = "";
}
class ProductItem
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Desc { get; set; } = "";
    public List<string> Tags { get; set; } = new();
    public string Icon { get; set; } = "";
    public string? Image { get; set; }
}
class RegisterDto
{
    public string? Name { get; set; }
    public string? Phone { get; set; }
    public string? Password { get; set; }
    public string? Confirm { get; set; }
}
class LoginDto
{
    public string? Account { get; set; }
    public string? Password { get; set; }
    public string? CaptchaId { get; set; }
    public string? Captcha { get; set; }
}
class TokenPayload
{
    public TokenPayload() { }
    public TokenPayload(string uid, long exp) { Uid = uid; Exp = exp; }
    public string Uid { get; set; } = "";
    public long Exp { get; set; }
}
