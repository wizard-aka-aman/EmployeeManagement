using EmployeeManagement.Models; 
using Microsoft.EntityFrameworkCore;
using NLog.Extensions.Logging;
using Microsoft.AspNetCore.Identity;
using EmployeeManagement.Security;
var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("EmployeeDBConnection") ?? throw new InvalidOperationException("Connection string 'EmployeeDBConnection' not found.");
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(
        builder.Configuration["ConnectionStrings:EmployeeDBConnection"]);
});


builder.Services.Configure<DataProtectionTokenProviderOptions>(o =>
    // changes  token  life span  of all token types
    o.TokenLifespan = TimeSpan.FromHours(5));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{

    options.Password.RequiredLength = 10;
    options.Password.RequiredUniqueChars = 3;
    options.Password.RequireNonAlphanumeric = false;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

 

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
});


//builder.Logging.ClearProviders();
//builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
//builder.Logging.AddConsole();
//builder.Logging.AddDebug();
//builder.Logging.AddEventSourceLogger();
//builder.Logging.AddNLog(); // Add NLog


//builder.Services.AddMvc();
builder.Services.AddControllersWithViews();

//builder.Services.AddAuthentication()
//    .AddGoogle(options =>
//        {
//            options.ClientId = "559611797951-vn5qcaja2732cc91ais5p89ii6slvvd7.apps.googleusercontent.com";
//            options.ClientSecret = "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";
//        })
     //.AddFacebook(options =>
     //{
     //    options.AppId = "2869287079898820";
     //    options.AppSecret = "ac061179be453be0acd334abb7eb66c5";
     //});

; 

builder.Services.ConfigureApplicationCookie(options =>
{
    options.AccessDeniedPath = new PathString("/Admin/AccessDenied");
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DeleteRolePolicy",
        policy => policy.RequireClaim("Delete Role", "true"));

    // this is used for the single use of policy for multiple uses of policy like AND or OR operator then we use Delegates  or requiredAssertions.
    //options.AddPolicy("EditRolePolicy",
    //policy => policy.RequireClaim("Edit Role", "true"));


    options.AddPolicy("EditRolePolicy", policy => policy.RequireAssertion(context =>
        context.User.IsInRole("Admin") &&
        context.User.HasClaim(claim => claim.Type == "Edit Role" && claim.Value == "true") ||
        context.User.IsInRole("Super Admin")
    ));



    options.AddPolicy("AdminRolePolicy",
        policy => policy.RequireRole("Admin"));
});

//builder.Services.AddSingleton<IEmployeeRepository, MockEmployeeRepository>();
builder.Services.AddScoped<IEmployeeRepository, SQLEmployeeRepository>();

builder.Services.AddSingleton<DataProtectionPurposeStrings>();
 
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithRedirects("/Error/{0}");
}
//app.MapGet("/", () => "Hello World!");
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication(); 
app.UseAuthorization();
app.MapDefaultControllerRoute(); // its is default route controller=home action=Index {id?}.
 


app.Run();
