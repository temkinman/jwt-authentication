using System.ComponentModel.DataAnnotations;

namespace Basic.Models
{
    public class RevokeRequest
    {
        [Required]
        public string RefreshToken { get; set;}
    }
}
