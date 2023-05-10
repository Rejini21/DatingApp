using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SQLitePCL;

namespace API.Controllers
{
    public class Accountcontroller: BaseApiController
    {

        private readonly DataContext _context;
        private readonly ITokenService tokenService;
        public Accountcontroller(DataContext context, ITokenService tokenService)
        {
            this.tokenService = tokenService;
            _context = context;
        }
        
        [HttpPost("register")] //POST :api/account/register

        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.UserName))
                return BadRequest("Username is already taken");
            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = tokenService.CreateToken(user)
            };

        }    

        [HttpPost("login")]

        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
                var user = await _context.Users.SingleOrDefaultAsync(x=>x.UserName == loginDto.UserName);
                if(user == null) return Unauthorized("Username is Invalid");

                using var hmac = new HMACSHA512(user.PasswordSalt);
                var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

                for (int i=0; i<computeHash.Length; i++)
                {
                    if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Password is incorrect");

                }
                 return new UserDto
                {
                    Username = user.UserName,
                    Token = tokenService.CreateToken(user)
                };

        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x=> x.UserName == username.ToLower());
        }
    }
}