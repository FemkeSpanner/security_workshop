using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;

namespace security_workshop.Services
{
    public class SeedDataService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IPasswordHasher<IdentityUser> _passwordHasher;

        public SeedDataService(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IPasswordHasher<IdentityUser> passwordHasher)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _roleManager = roleManager ?? throw new ArgumentNullException(nameof(roleManager));
            _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
        }

        public async Task InitializeAsync(ModelBuilder modelBuilder)
        {
            await SeedRolesAsync(modelBuilder);
            await SeedUsersAsync(modelBuilder);
        }

        private async Task SeedRolesAsync(ModelBuilder modelBuilder)
        {
            string[] roleIds = { "1", "2", "3" };
            string[] roleNames = { "Admin", "Moderator", "Player" };

            for (int i = 0; i < roleNames.Length; i++)
            {
                if (!await _roleManager.RoleExistsAsync(roleNames[i]))
                {
                    var role = new IdentityRole
                    {
                        Id = roleIds[i],
                        Name = roleNames[i],
                        NormalizedName = roleNames[i].ToUpper()
                    };

                    modelBuilder.Entity<IdentityRole>().HasData(role);

                    await _roleManager.CreateAsync(role);
                }
            }
        }

        private async Task SeedUsersAsync(ModelBuilder modelBuilder)
        {
            if (await _userManager.FindByNameAsync("Femke") == null)
            {
                var user = new IdentityUser
                {
                    UserName = "Femke",
                    NormalizedUserName = "FEMKE",
                    Email = "voorbeeld@live.nl",
                    NormalizedEmail = "VOORBEELD@LIVE.NL",
                    EmailConfirmed = true
                };

                var password = "Voorbeeld123voorbeeld!";
                var hashedPassword = _passwordHasher.HashPassword(user, password);
                user.PasswordHash = hashedPassword;

                modelBuilder.Entity<IdentityUser>().HasData(user);

                var result = await _userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, "Admin");
                }
                else
                {
                    // Handle errors if user creation or role assignment fails
                    throw new InvalidOperationException($"Could not create user: {string.Join(", ", result.Errors)}");
                }
            }
        }
    }
}
