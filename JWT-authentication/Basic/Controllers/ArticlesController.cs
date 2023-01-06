using Basic.Models;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace Basic.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ArticlesController : ControllerBase
    {
        private readonly ILogger<ArticlesController> _logger;
        private static List<Article> articles= new List<Article>();

        public ArticlesController(ILogger<ArticlesController> logger)
        {
            _logger = logger;
        }

        // GET: api/<ArticlesController>
        [HttpGet]
        public ActionResult<IEnumerable<Article>> GetArticles()
        {
            return Ok(articles);
        }

        // GET api/<ArticlesController>/5
        [HttpGet("{id}")]
        public ActionResult<Article> GetArticle(string id)
        {
            var article = articles.FirstOrDefault(x => x.Id.Equals(id));

            if(article == null)
            {
                return NotFound();
            }

            return Ok(article);
        }

        // POST api/<ArticlesController>
        [HttpPost]
        public ActionResult<Article> InsertArticle([FromBody] Article article)
        {
            article.Id = Guid.NewGuid().ToString();
            articles.Add(article);

            return CreatedAtAction(nameof(GetArticles), new { id = article.Id }, article);
        }

        // PUT api/<ArticlesController>/5
        [HttpPut("{id}")]
        public ActionResult<Article> UpdateArticle(string id, Article article)
        {
            if(id != article.Id)
            {
                return BadRequest();
            }

            var articleToUpdate = articles.FirstOrDefault(x => x.Id.Equals(id));

            if (articleToUpdate == null)
            {
                return NotFound();
            }

            articleToUpdate.Author = article.Author;
            articleToUpdate.Title = article.Title;
            articleToUpdate.Content= article.Content;
            articleToUpdate.UpVotes = article.UpVotes;
            articleToUpdate.Views= article.Views;

            return NoContent();
        }

        // DELETE api/<ArticlesController>/5
        [HttpDelete("{id}")]
        public ActionResult DeleteArticle(string id)
        {
            var articleToDelete = articles.FirstOrDefault(x => x.Id.Equals(id));

            if (articleToDelete == null)
            {
                return NotFound();
            }

            articles.Remove(articleToDelete);

            return NoContent();
        }
    }
}
