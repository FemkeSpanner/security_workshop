using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using security_workshop.Data;
using security_workshop.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.ConfigureApplicationCookie(options =>
{
    
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;

    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;

    options.LoginPath = "/Identity/Account/Login";
    options.AccessDeniedPath = "/Identity/Account/AccessDenied";
   
});
builder.Logging.ClearProviders();
builder.Services.AddControllersWithViews();

var app = builder.Build();
app.Use(async (context, next) =>
{
    // Cache headers om caching te voorkomen
    context.Response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
    context.Response.Headers.Pragma = "no-cache";
    context.Response.Headers.Expires = "-1";

    // Verwijderen van informatie headers van de server
    context.Response.Headers.Server = "";         // Verbergt de servernaam
    context.Response.Headers.XPoweredBy = "";   // Verbergt de gebruikte technologie


    // X-Frame-Options header voorkomt clickjacking
    context.Response.Headers.XFrameOptions = "DENY";

    // X-Xss-Protection activeert de XSS filter van de browser
    context.Response.Headers.XXSSProtection = "1; mode=block";

    // X-Content-Type-Options voorkomt MIME-sniffing
    context.Response.Headers.XContentTypeOptions = "nosniff";

    // Content Security Policy (CSP) beperkt bronnen die kunnen worden geladen
    context.Response.Headers.ContentSecurityPolicy = $"default-src 'none'; " +
        $"script-src 'self' https://code.jquery.com https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; " +
        $"style-src 'self' https://stackpath.bootstrapcdn.com; " +
        $"font-src 'self' https://stackpath.bootstrapcdn.com; " +
        $"img-src 'self' data: https://stackpath.bootstrapcdn.com; " +
        $"connect-src 'self' http://localhost:7068 https://localhost:7068';";

    // Strict Transport Security (HSTS) header dwingt HTTPS-gebruik af
    context.Response.Headers.Append("Strict-Transport-Security", "max-age=15724800; includeSubdomains");

    // Cross-Origin Resource Sharing (CORS) headers voor toegangscontrole
    context.Response.Headers.AccessControlAllowOrigin = "https://localhost";
    context.Response.Headers.AccessControlAllowHeaders = "Content-Type, Authorization";
    context.Response.Headers.AccessControlAllowMethods = "GET, POST, PUT, DELETE, OPTIONS";

    // Referrer Policy header bepaalt hoe de referrer wordt meegestuurd
    context.Response.Headers["Referrer-Policy"] = "same-origin";

    await next();
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
