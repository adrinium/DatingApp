using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDTO)
        {
            if (await UserExists(registerDTO.UserName)) return BadRequest("user already exists");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDTO.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
                PasswordSalt = hmac.Key,
            };

            _context.Users.Add(user);

            await _context.SaveChangesAsync();

            return new UserDTO
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user),
            };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDTO)
        {
            var user = await _context.Users.SingleOrDefaultAsync(user => user.UserName == loginDTO.UserName);

            if (user == null) return Unauthorized("Invalid request");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");
            }

            return new UserDTO
            {
                UserName = user.UserName,
                Token = _tokenService.CreateToken(user),
            };
        }
    }
}