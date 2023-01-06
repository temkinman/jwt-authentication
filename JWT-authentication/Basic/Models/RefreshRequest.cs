using System.ComponentModel.DataAnnotations;

namespace Basic.Models
{
    public class RefreshRequest
    {
        [Required]
        public string RefreshToken { get; set; }
    }
}
